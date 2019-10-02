#ifndef TLVMutator_hpp_included
#define TLVMutator_hpp_included

// for the custom mutator

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <random>
#include <tuple>
#include <vector>

struct Block
{
  Block(uint16_t type, const uint8_t* Data, uint8_t Size)
    : m_type(type)
  {
    m_data.assign(Data, Data + Size);
  }
  uint16_t m_type;
  /// length of data in bytes
  size_t datalen() const { return m_data.size(); }
  uint8_t* data() { return m_data.data(); }
  const uint8_t* data() const { return m_data.data(); }
  std::vector<uint8_t> m_data;

  /// total size in bytes, including header and data
  size_t sizeInBytes() const
  {
    return sizeof(uint16_t) + sizeof(uint32_t) + datalen();
  }
  void prettyPrint() const;
};

// std::vector<Block> splitIntoBlocks(const uint8_t* Data, size_t Size);

struct BlockHolder
{
  enum BlockSelection
  {
    // the type
    INCLUDE_FLAG = 1 << 0,
    INCLUDE_STRING = 1 << 2,
    INCLUDE_OTHER = 1 << 3,
    // if its interesting or not
    ALLOW_INTERESTING = 1 << 4,
    ALLOW_NOT_INTERESTING = 1 << 5,
    // if it can be given once or more
    ALLOW_NONCOMPOSITING = 1 << 6,
    ALLOW_COMPOSITING = 1 << 6,
  };
  explicit BlockHolder(unsigned int Seed)
    : m_engine(Seed)
  {}
  void initializeFromBuffer(const uint8_t* Data, size_t Size);
  size_t totalSizeInBytes() const;
  template<class Integer>
  Integer getInteger(Integer min, Integer max)
  {
    if (min == max) {
      return min;
    }
    assert(min < max);
    return std::uniform_int_distribution<Integer>(min, max)(m_engine);
  }

  uint16_t makeRandomTLVType();
  /// makes a garbage block and returns it, does not insert it
  Block makeGarbage(int tlvtype, const size_t len, const bool printable_ascii);
  bool insertGarbage(const size_t len, const bool printable_ascii);
  Block& pickRandomBlock();
  Block* pickRandomBlock(bool must_be_interesting,
                         bool can_be_flags,
                         bool can_be_string);

  /// picks two random blocks if possible, subject to restriction from the
  /// selection bitmask (ored from BlockSelection)
  std::tuple<Block*, Block*> pickRandomBlocks(
    unsigned selection,
    unsigned composition = ALLOW_COMPOSITING | ALLOW_NONCOMPOSITING);

  std::vector<Block>::iterator iterator_at(size_t index);
  std::vector<Block>::iterator iterator_at(std::ptrdiff_t index);
  Block& at(size_t index);
  Block& at(std::ptrdiff_t index);
  /// mutates the content of a single block, without
  /// changing the type
  bool mutateSingleBlock();
  bool mutateSingleBlock(size_t index);
  bool mutateSingleBlock(Block& block);
  bool mutateSingleBlock(Block* block);

  bool mutateManyBlocks(size_t howmany);
  // picks a random interesting block and mutates it
  bool mutateInterestingBlock(bool can_be_string);

  /// returns true if one was deleted
  bool deleteBlock();
  /// swaps the place of two random blocks
  bool swapBlocks();
  bool swapTypes();
  bool duplicateBlockAsAnotherType();
  bool rotateBlocks();
  bool mutateType();
  /// makes a copy of an existing block, mutates the payload with
  /// libFuzzer's mutation
  bool llvmMutatedCopy();
  /// applies a random mutation
  bool mutateBlindly();

  /// adds random elements, good in case
  /// one needs to start from empty
  void bootstrap(size_t MaxSize);

  /// returns true if a mutation took place
  bool mutate(size_t MaxSize);
  /// picks a random flag block and mutates it
  bool mutateFlagBlock();
  /// picks a random interesting block and mutates it
  bool mutateInterestingBlock();

  /// makes a new block from thin air and inserts it (replaces an existing one,
  /// in case it does not compose)
  bool insertNewBlockFromThinAir(unsigned selection);

  /// returns true if at least one was removed
  bool removeRedundant();
  /// flattens the blocks to the given buffer
  /// returns the number of bytes written
  size_t flattenToBuffer(uint8_t* Data, size_t Size);
  /// size in number of blocks
  size_t size() const { return m_blocks.size(); }
  /// size in number of blocks
  std::ptrdiff_t ssize() const
  {
    return static_cast<std::ptrdiff_t>(m_blocks.size());
  }
  bool empty() const { return m_blocks.empty(); }

  /// splices other into this
  void splice(BlockHolder& other);
  void splice_a_then_b(BlockHolder& other);
  void splice_nibbled(BlockHolder& other);
  void prettyPrint();
  /// sorts the block in such a way that
  /// they get a predictable placement
  void sortBlocks();

private:
  std::minstd_rand m_engine;
  std::vector<Block> m_blocks;
};

#endif // TLVMutator_hpp_included
