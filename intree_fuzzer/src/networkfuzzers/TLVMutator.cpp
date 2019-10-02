
#include "TLVMutator.hpp"
#include "TLVMacros.hh"
#include "TLVTraits.hpp"
#include "bogus.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <random>
#include <set>
#include <stdint.h>
#include <tuple>
#include <vector>

static const TLVTraits traits;

extern "C" size_t
LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

extern "C" size_t
curl_LLVMFuzzerCustomMutator(uint8_t* Data,
                             size_t Size,
                             size_t MaxSize,
                             unsigned int Seed)
{
  assert(Data);
  BlockHolder h(Seed);

  // split the incoming data into tlv tuples
  h.initializeFromBuffer(Data, Size);

  // h.prettyPrint();

  h.removeRedundant();

  // in case of empty, bootstrap
  if (h.empty()) {
    h.bootstrap(MaxSize);
  }
  // mutate (try a few times, until something happened)
  int ntries = 1;
  do {
    if (h.mutate(MaxSize)) {
      break;
    }
  } while (++ntries < 10);
  h.removeRedundant();

  const size_t sizebefore = h.totalSizeInBytes();
  // make sure it will fit in the buffer given
  while (h.totalSizeInBytes() > MaxSize) {
    h.deleteBlock();
  }
  if (false) {
    std::cout << "sizebefore=" << sizebefore << "\tSize=" << Size
              << "\tMaxSize=" << MaxSize << std::endl;
  }

  // sort, so the output is stable
  h.sortBlocks();

  const size_t newsize = h.flattenToBuffer(Data, MaxSize);
  assert(newsize <= MaxSize);
  return newsize;
}

// Optional user-provided custom cross-over function.
// Combines pieces of Data1 & Data2 together into Out.
// Returns the new size, which is not greater than MaxOutSize.
// Should produce the same mutation given the same Seed.
extern "C" size_t
LLVMFuzzerCustomCrossOver(const uint8_t* Data1,
                          size_t Size1,
                          const uint8_t* Data2,
                          size_t Size2,
                          uint8_t* Out,
                          size_t MaxOutSize,
                          unsigned int Seed);
extern "C" size_t
curl_LLVMFuzzerCustomCrossOver(const uint8_t* Data1,
                               size_t Size1,
                               const uint8_t* Data2,
                               size_t Size2,
                               uint8_t* Out,
                               size_t MaxOutSize,
                               unsigned int Seed)
{
  BlockHolder h1(Seed);
  BlockHolder h2(Seed);
  // split the incoming data into tlv tuples
  h1.initializeFromBuffer(Data1, Size1);
  h2.initializeFromBuffer(Data2, Size2);

  const size_t N1 = h1.size();
  const size_t N2 = h2.size();
  if (N1 == 0 || N2 == 0) {
    // refuse to work with silly inputs
    return 0;
  }

  // splice a random number of elements from 1 with 2
  h1.splice(h2);
  h1.removeRedundant();

  // make sure it fits
  while (h1.totalSizeInBytes() > MaxOutSize) {
    h1.deleteBlock();
  }

  // make the output stable
  h1.sortBlocks();

  // serialize
  return h1.flattenToBuffer(Out, MaxOutSize);
}

std::vector<Block>
splitIntoBlocks(const uint8_t* Data, size_t Size)
{
  std::vector<Block> ret;
  size_t i = 0;
  const size_t minblocksize = sizeof(uint16_t) + sizeof(uint32_t);
  while (i + minblocksize <= Size) {

    std::uint16_t tmp16;
    std::memcpy(&tmp16, Data + i, sizeof(tmp16));
    auto type = __builtin_bswap16(tmp16);
    i += sizeof(tmp16);

    std::uint32_t tmp32;
    std::memcpy(&tmp32, Data + i, sizeof(tmp32));
    auto len = __builtin_bswap32(tmp32);
    i += sizeof(tmp32);

    const uint8_t* data = len ? Data + i : nullptr;
    i += len;

    // reject invalid types
    if (type < TLV_TYPE_LOWEST || type > TLV_TYPE_HIGHEST) {
      continue;
    }
    if (!traits.isValidType(type)) {
      continue;
    }
    // reject data of the wrong length
    if (!traits.isValidLength(type, len)) {
      continue;
    }

    // do not allow to point outside of Data
    if (i <= Size) {
      ret.emplace_back(type, data, len);
    }
  }
  const auto nleftover = Size - i;
  (void)nleftover;
  return ret;
}

void
BlockHolder::initializeFromBuffer(const uint8_t* Data, size_t Size)
{
  m_blocks = splitIntoBlocks(Data, Size);
}

size_t
BlockHolder::totalSizeInBytes() const
{
  size_t total_size = 0;
  for (const auto& b : m_blocks) {
    total_size += b.sizeInBytes();
  }
  return total_size;
}

uint16_t
BlockHolder::makeRandomTLVType()
{
  return getInteger<uint16_t>(TLV_TYPE_LOWEST, TLV_TYPE_HIGHEST);
}

Block
BlockHolder::makeGarbage(int tlvtype,
                         const size_t len,
                         const bool printable_ascii)
{
  // these are the printable ascii, plus control characters relevant
  // for this application (text based, line oriented protocols)

  // does this look weird? it gets optimized into a compile time
  // array, without any mutex locking etc (magic statics).
  const auto chars = []() {
    const int max_printable_ascii = 0x7E;
    const int min_printable_ascii = 0x20;
    const int nof_controlchars = 2;
    const int nof_printable = max_printable_ascii - min_printable_ascii;
    const int arraylen = nof_printable + nof_controlchars;
    std::array<uint8_t, arraylen> chars;
    int i = 0;
    for (i = 0; i < nof_printable; ++i) {
      chars.at(i) = min_printable_ascii + i;
    }
    chars.at(i++) = '\r';
    chars.at(i++) = '\n';
    assert(i == arraylen);
    return chars;
  }();

  Block b(tlvtype, nullptr, 0);

  b.m_data.reserve(len);
  if (printable_ascii) {
    for (size_t i = 0; i < len; ++i) {
      b.m_data.push_back(chars.at(getInteger<size_t>(0, chars.size() - 1)));
    }
  } else {
    for (size_t i = 0; i < len; ++i) {
      b.m_data.push_back(getInteger<uint8_t>(0, 255));
    }
  }
  return b;
}

bool
BlockHolder::insertGarbage(const size_t len, const bool printable_ascii)
{
  const size_t index1 = getInteger<size_t>(0, m_blocks.size());
  Block b = makeGarbage(makeRandomTLVType(), len, printable_ascii);
  m_blocks.insert(iterator_at(index1), std::move(b));
  return true;
}

Block&
BlockHolder::pickRandomBlock()
{
  assert(!empty());
  auto index = getInteger(std::ptrdiff_t{ 0 }, ssize() - 1);
  return at(index);
}

Block*
BlockHolder::pickRandomBlock(bool must_be_interesting,
                             bool can_be_flags,
                             bool can_be_string)
{
  std::vector<Block*> blocks;
  blocks.reserve(m_blocks.size());
  for (auto& b : m_blocks) {
    const auto type = b.m_type;
    const auto t = traits.findOptionByTlvType(type);
    if (!t) {
      continue;
    }
    if (must_be_interesting && !t->isInteresting()) {
      continue;
    }
    if (can_be_flags && t->isFlag()) {
      blocks.push_back(&b);
    } else if (can_be_string && t->isString()) {
      blocks.push_back(&b);
    }
  }
  if (blocks.empty()) {
    return nullptr;
  }
  size_t index = getInteger<size_t>(0, blocks.size() - 1);
  return blocks.at(index);
}

std::tuple<Block*, Block*>
BlockHolder::pickRandomBlocks(const unsigned selection, unsigned composition)
{
  const bool allow_interesting = (selection & ALLOW_INTERESTING);
  const bool allow_not_interesting = (selection & ALLOW_NOT_INTERESTING);
  const bool include_flag = (selection & INCLUDE_FLAG);
  const bool include_string = (selection & INCLUDE_STRING);
  const bool include_other = (selection & INCLUDE_OTHER);

  const bool allow_noncomposite = (composition & ALLOW_NONCOMPOSITING);
  const bool allow_composite = (composition & ALLOW_COMPOSITING);

  std::vector<Block*> blocks;
  blocks.reserve(m_blocks.size());
  for (auto& b : m_blocks) {
    const auto type = b.m_type;
    const auto t = traits.findOptionByTlvType(type);
    if (!t) {
      // illegal type
      continue;
    }
    if ((t->isInteresting() && allow_interesting) ||
        (!t->isInteresting() && allow_not_interesting)) {
      if ((include_flag && t->isFlag()) || (include_string && t->isString()) ||
          (include_other && t->isOther())) {
        if ((allow_composite && t->canBeSetMoreThanOnce()) ||
            (allow_noncomposite && !t->canBeSetMoreThanOnce())) {
          blocks.push_back(&b);
        }
      }
    }
  }
  Block* ret0{};
  Block* ret1{};

  if (blocks.size() > 0) {
    size_t index0 = getInteger<size_t>(0, blocks.size() - 1);
    ret0 = blocks.at(index0);
    blocks.erase(blocks.begin() + index0);
  }
  if (blocks.size() > 0) {
    size_t index1 = getInteger<size_t>(0, blocks.size() - 1);
    ret1 = blocks.at(index1);
  }
  return { ret0, ret1 };
}

std::vector<Block>::iterator
BlockHolder::iterator_at(size_t index)
{
  assert(index <= size());
  return m_blocks.begin() + static_cast<std::ptrdiff_t>(index);
}

std::vector<Block>::iterator
BlockHolder::iterator_at(std::ptrdiff_t index)
{
  assert(index >= 0);
  assert(index <= ssize());
  return m_blocks.begin() + index;
}

Block&
BlockHolder::at(size_t index)
{
  assert(index < size());
  return m_blocks.at(index);
}

Block&
BlockHolder::at(std::ptrdiff_t index)
{
  assert(index >= 0);
  assert(index < ssize());
  return m_blocks.at(static_cast<size_t>(index));
}

bool
BlockHolder::mutateSingleBlock()
{
  assert(!m_blocks.empty());

  size_t index = getInteger<size_t>(0, size() - 1);
  return mutateSingleBlock(index);
}

bool
BlockHolder::mutateSingleBlock(size_t index)
{
  Block& b = at(index);
  return mutateSingleBlock(b);
}

bool
BlockHolder::mutateSingleBlock(Block& b)
{
  // what type is this block?
  const CurlOption* t{};

  t = traits.findOptionByTlvType(b.m_type);

  // if the block is garbage, flip the type and try again
  while (t == nullptr) {
    b.m_type = makeRandomTLVType();
    t = traits.findOptionByTlvType(b.m_type);
  }

  if (t->isFlag()) {
    // fixed size, so mutate the content, in place
    // in case this was garbage coming in, resize it.
    b.m_data.resize(4);
    LLVMFuzzerMutate(b.data(), b.datalen(), b.datalen());
    return true;
  }

  // variable length, so allow the length to be modified

  size_t size_now = b.datalen();
  size_t new_size = 0;

  if (size_now < 50) {
    new_size = 100;
  } else {
    new_size = 2 * size_now;
  }
  b.m_data.resize(new_size);
  new_size = LLVMFuzzerMutate(b.m_data.data(), size_now, new_size);
  b.m_data.resize(new_size);
  return true;
}

bool
BlockHolder::mutateSingleBlock(Block* block)
{
  if (block) {
    return mutateSingleBlock(*block);
  } else {
    return false;
  }
}

bool
BlockHolder::mutateManyBlocks(size_t howmany)
{
  assert(howmany > 0);

  if (howmany >= size()) {
    for (size_t i = 0; i < size(); ++i) {
      mutateSingleBlock(i);
    }
    return size() != 0;
  }

  std::set<size_t> indices;
  while (indices.size() < howmany) {
    indices.insert(getInteger<size_t>(0, size() - 1));
  }
  for (const auto& i : indices) {
    mutateSingleBlock(i);
  }
  return true;
}

bool
BlockHolder::deleteBlock()
{
  if (m_blocks.empty()) {
    return false;
  }
  size_t index = this->getInteger<size_t>(0, m_blocks.size());
  m_blocks.erase(iterator_at(index));
  return true;
}

bool
BlockHolder::swapBlocks()
{
  if (m_blocks.size() < 2) {
    return false;
  }
  // pick one at random.
  size_t N = m_blocks.size() - 1;
  size_t index1 = getInteger<size_t>(0, N);
  size_t index2 = index1;
  do {
    index2 = getInteger<size_t>(0, N);
  } while (index2 == index1);

  std::swap(m_blocks.at(index1), m_blocks.at(index2));
  return true;
}

bool
BlockHolder::swapTypes()
{
  if (m_blocks.size() < 2) {
    return false;
  }
  // pick one at random.
  size_t N = m_blocks.size() - 1;
  size_t index1 = getInteger<size_t>(0, N);
  size_t index2 = index1;
  do {
    index2 = getInteger<size_t>(0, N);
  } while (index2 == index1);

  std::swap(m_blocks.at(index1).m_type, m_blocks.at(index2).m_type);
  return true;
}

bool
BlockHolder::duplicateBlockAsAnotherType()
{
  if (m_blocks.size() < 1) {
    return false;
  }
  // pick one at random.
  Block copy = pickRandomBlock();
  // change the type
  auto current_type = copy.m_type;
  do {
    copy.m_type = makeRandomTLVType();
  } while (current_type == copy.m_type);

  const size_t index = getInteger<size_t>(0, m_blocks.size());
  m_blocks.insert(iterator_at(index), std::move(copy));
  return true;
}

bool
BlockHolder::rotateBlocks()
{
  if (m_blocks.size() < 2) {
    return false;
  }
  // pick a mid element at random.
  size_t index1 = getInteger<size_t>(1, m_blocks.size() - 1);
  std::rotate(m_blocks.begin(), iterator_at(index1), m_blocks.end());
  return true;
}

bool
BlockHolder::mutateType()
{
  if (m_blocks.empty()) {
    return false;
  }
  auto& type = pickRandomBlock().m_type;
  const auto origtype = type;
  do {
    type = makeRandomTLVType();
  } while (type == origtype);
  return true;
}

bool
BlockHolder::llvmMutatedCopy()
{
  if (m_blocks.empty()) {
    return false;
  }
  for (int i = 0; i < 10; ++i) {
    Block& b = pickRandomBlock();
    if (b.datalen() == 0) {
      // not interesting, does probably not need a payload
      continue;
    }
    // make room for mutation
    Block copy = b;
    const auto original_len = copy.datalen();
    copy.m_data.resize(original_len + 50);
    // invoke libfuzzer
    const size_t new_len =
      LLVMFuzzerMutate(copy.m_data.data(), original_len, copy.m_data.size());
    copy.m_data.resize(new_len);
    // insert it at a random location
    const size_t index = getInteger<size_t>(0, m_blocks.size());
    m_blocks.insert(iterator_at(index), std::move(copy));
    return true;
  }
  return false;
}

bool
BlockHolder::mutateBlindly()
{
  // select a mutation
  switch (getInteger<int>(0, 7)) {
    case 0:
      // let mutation of multiple blocks be
      // taken care by the "stacked tweaks" functionality
      // in libfuzzer
      return mutateSingleBlock();
    case 1:
      return deleteBlock();
    case 2:
      return duplicateBlockAsAnotherType();

    case 3:
      return mutateType();

    case 4:
      // newly made up ascii garbage
      return insertGarbage(getInteger<size_t>(0, 1000), true);

    case 5:
      // binary garbage
      return insertGarbage(getInteger<size_t>(0, 10), false);

    case 6:
      return llvmMutatedCopy();
    case 7:
      // swap types between two existing blocks.
      return swapTypes();

    default:
      return false;
  }
}

void
BlockHolder::bootstrap(size_t MaxSize)
{
  // make an uninteresting string, good for boot strapping.
  for (int i = 0; i < 2; ++i) {
    insertNewBlockFromThinAir(BlockSelection::ALLOW_NOT_INTERESTING |
                              BlockSelection::INCLUDE_STRING);
  }
  // then a flag...
  insertNewBlockFromThinAir(BlockSelection::ALLOW_NOT_INTERESTING |
                            BlockSelection::INCLUDE_FLAG);

  // and then some payload
  do {
    insertNewBlockFromThinAir(BlockSelection::ALLOW_INTERESTING |
                              BlockSelection::INCLUDE_STRING);
  } while (this->totalSizeInBytes() < MaxSize);
}

bool
BlockHolder::mutate(size_t MaxSize)
{
  assert(!empty());

  const auto dice = getInteger<int>(0, 10000);

  if (dice <= 0) {
    // rare occasion. use the old strategy.
    return mutateBlindly();
  }

  if (dice <= 1) {
    // mutate one of the not so interesting flags
    auto b = pickRandomBlocks(BlockSelection::ALLOW_NOT_INTERESTING |
                              BlockSelection::INCLUDE_FLAG);
    return mutateSingleBlock(std::get<0>(b));
  }
  if (dice <= 2) {
    // mutate one of the not so interesting strings
    auto b = pickRandomBlocks(BlockSelection::ALLOW_NOT_INTERESTING |
                              BlockSelection::INCLUDE_STRING);
    return mutateSingleBlock(std::get<0>(b));
  }
  if (dice <= 3) {
    // insert a newly made up uninteresting block
    return insertNewBlockFromThinAir(BlockSelection::ALLOW_NOT_INTERESTING |
                                     BlockSelection::INCLUDE_STRING |
                                     BlockSelection::INCLUDE_FLAG);
  }
  if (dice <= 4) {
    // swap the position of two interesting compositing blocks
    auto [b0, b1] = pickRandomBlocks(BlockSelection::ALLOW_INTERESTING |
                                       BlockSelection::INCLUDE_STRING,
                                     ALLOW_COMPOSITING);
    if (b0 && b1) {
      std::iter_swap(b0, b1);
      return true;
    }
    return false;
  }
  if (dice <= 5) {
    // this was an attemt to get around the fact that libfuzzer does
    // keep MaxSize low, which means it is difficult to get generate
    // respones large enough
    m_blocks.clear();
    bootstrap(MaxSize);
    return true;
  }
  if (dice <= 10000) {
    // mutate an interesting string
    auto b = pickRandomBlocks(BlockSelection::ALLOW_INTERESTING |
                              BlockSelection::INCLUDE_STRING);
    return mutateSingleBlock(std::get<0>(b));
  }
  return false;
}

bool
BlockHolder::mutateFlagBlock()
{
  Block* b = pickRandomBlock(false, true, false);
  if (b) {
    return mutateSingleBlock(*b);
  }
  return false;
}

bool
BlockHolder::insertNewBlockFromThinAir(unsigned selection)
{
  // which type of block should we make?
  /*
  INCLUDE_FLAG = 1<<0,
  INCLUDE_STRING= 1<<2,
  INCLUDE_OTHER= 1<<3,
  ALLOW_INTERESTING= 1<<4,
  ALLOW_NOT_INTERESTING= 1<<5
  */
  uint16_t type{};
  const CurlOption* t{};
  for (;;) {
    type = makeRandomTLVType();
    t = traits.findOptionByTlvType(type);
    if (t) {
      if (((selection & INCLUDE_FLAG) && t->isFlag()) ||
          ((selection & INCLUDE_STRING) && t->isString()) ||
          ((selection & INCLUDE_OTHER) && t->isOther())) {
        if (((selection & ALLOW_INTERESTING) && t->isInteresting()) ||
            ((selection & ALLOW_NOT_INTERESTING) && !t->isInteresting())) {
          break;
        }
      }
    }
  }

  Block b = [&]() {
    if (t->isFlag()) {
      return makeGarbage(type, 4, false);
    }
    if (t->isString() && !t->isInteresting()) {
      // random short length string
      return makeGarbage(type, getInteger(4, 30), true);
    }
    if (t->isString() && t->isInteresting()) {
      // random long length string
      return makeGarbage(type, getInteger(0, 200), true);
    }
    return makeGarbage(type, getInteger(0, 200), false);
  }();

  if (!t->canBeSetMoreThanOnce()) {
    for (std::size_t i = 0; i < m_blocks.size(); ++i) {
      if (at(i).m_type == type) {
        std::swap(at(i), b);
        return true;
      }
    }
  }
  // insert it at some random place
  const size_t index = getInteger<size_t>(0, m_blocks.size());
  m_blocks.insert(iterator_at(index), std::move(b));
  return true;
}

bool
BlockHolder::removeRedundant()
{
  // which we have seen so far
  std::set<decltype(Block::m_type)> seen;

  int nremoved = 0;
  for (size_t i = 0; i < m_blocks.size(); ++i) {
    const auto type = m_blocks.at(i).m_type;
    if (seen.count(type)) {
      if (!traits.canBeSetMoreThanOnce(type)) {
        m_blocks.erase(m_blocks.begin() + i);
        ++nremoved;
      }
    } else {
      seen.insert(type);
    }
  }
  return nremoved != 0;
}

size_t
BlockHolder::flattenToBuffer(uint8_t* Data, size_t Size)
{
  // make sure all blocks fit
  const size_t total_size = totalSizeInBytes();
  assert(Size >= total_size);
  for (const auto& b : m_blocks) {
    const auto type_be = __builtin_bswap16(b.m_type);
    std::memcpy(Data, &type_be, sizeof(uint16_t));
    Data += sizeof(uint16_t);
    Size -= sizeof(uint16_t);

    const auto len_be = __builtin_bswap32(static_cast<uint32_t>(b.datalen()));
    std::memcpy(Data, &len_be, sizeof(uint32_t));
    Data += sizeof(uint32_t);
    Size -= sizeof(uint32_t);

    if (b.datalen() > 0) {
      std::memcpy(Data, b.m_data.data(), b.datalen());
      Data += b.datalen();
      Size -= b.datalen();
    }
  }
  return total_size;
}

void
BlockHolder::splice(BlockHolder& other)
{
  assert(!empty());
  assert(!other.empty());

  switch (getInteger(0, 1)) {
    case 0:
      splice_a_then_b(other);
      return;
    case 1:
      splice_nibbled(other);
      return;
  }
  assert(false);
}

void
BlockHolder::splice_a_then_b(BlockHolder& other)
{
  // the idea is to take the first N blocks of this, contatenated with
  // the last M blocks of other, with N and M selected at random
  const auto N = this->getInteger<ptrdiff_t>(1, ssize());
  const auto M = this->getInteger<ptrdiff_t>(1, other.ssize());
  std::vector<Block> spliced(m_blocks.begin(), m_blocks.begin() + N);
  spliced.insert(spliced.end(),
                 other.m_blocks.begin() + (other.ssize() - M),
                 other.m_blocks.end());
  m_blocks.swap(spliced);
}

void
BlockHolder::splice_nibbled(BlockHolder& other)
{
  std::vector<Block> spliced;
  const auto S1 = size();
  const auto S2 = other.size();
  for (size_t i = 0; i < S1 || i < S2; ++i) {
    int source = -1;
    if (i < S1 && i < S2) {
      // within both ranges, pick at random
      source = getInteger(1, 2);
    } else if (i < S1) {
      source = 1;
    } else if (i < S2) {
      source = 2;
    }
    switch (source) {
      case 1:
        spliced.insert(spliced.end(), this->at(i));
        break;
      case 2:
        spliced.insert(spliced.end(), other.at(i));
        break;
    }
  }
  m_blocks.swap(spliced);
}

void
BlockHolder::prettyPrint()
{
  std::ostream& os(std::cout);
  int i = 0;
  for (const auto& b : m_blocks) {
    os << " block " << i << "/" << size() << ": ";
    b.prettyPrint();
    ++i;
  }
}

void
BlockHolder::sortBlocks()
{
  std::stable_sort(
    m_blocks.begin(), m_blocks.end(), [](const Block& a, const Block& b) {
      // return std::tuple{ a.m_type, a.datalen() } < std::tuple{ b.m_type,
      // b.datalen() };
      return a.m_type < b.m_type;
    });
}
const char*
tlvToString(int type)
{
  switch (type) {
    case TLV_TYPE_URL:
      return "TLV_TYPE_URL";

    default:
      return "unknown";
  }
}
void
Block::prettyPrint() const
{
  std::ostream& os(std::cout);
  os << tlvToString(m_type) << ": ";
  if (m_data.data()) {
    os << "\"";
    os.write((const char*)m_data.data(), m_data.size());
    os << "\"";
  } else
    os << "NULL";
}
