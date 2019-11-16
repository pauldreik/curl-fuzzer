/*
 * For running the fuzz target recursively on files/directories given to main.
 * Paul Dreik 2019
 */
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <iostream>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t);

namespace bf = boost::filesystem;

static void
invokeFuzzer(const bf::path &p)
{
  //    LLVMFuzzerTestOneInput(buffer, buffer_len);

  static long counter = 0;

  ++counter;

  std::cout << "Running on file " << counter << ": " << p << '\n';

  const auto filesize = bf::file_size(p);
  if(0 == filesize) {
    LLVMFuzzerTestOneInput(nullptr, 0);
    return;
  }
  // slurp the file
  bf::ifstream file(p);
  assert(file);

  // use heap allocated memory of the exact size, to maximize the
  // probability of address sanitizer detecting memory errors
  auto buffer = std::make_unique<uint8_t[]>(filesize);
  file.read((char *)buffer.get(), filesize);
  assert(file.gcount() == filesize);
  LLVMFuzzerTestOneInput(buffer.get(), filesize);
}

// does a recursive walk (following symlinks)
template <class Action>
static void
invoke_on_all_regular_files(bf::path p, Action action)
{

  if(bf::is_directory(p)) {
    bf::recursive_directory_iterator iter(p, bf::symlink_option::recurse);
    bf::recursive_directory_iterator end;
    for(; iter != end; ++iter) {
      auto child = iter->path();
      if(!bf::is_directory(child)) {
        invoke_on_all_regular_files(child, action);
      }
    }
  }
  else if(bf::is_regular_file(p)) {
    action(p);
  }
  else if(bf::is_symlink(p)) {
    // dereference the symlink
    invoke_on_all_regular_files(bf::read_symlink(p), action);
  }
  // anything else (chacter devices etc, non-existant stuff) is ignored
}

int
main(int argc, char **argv)
{

  for(int i = 1; i < argc; ++i) {
    invoke_on_all_regular_files(argv[i],
                                [](auto file) { invokeFuzzer(file); });
  }
}
