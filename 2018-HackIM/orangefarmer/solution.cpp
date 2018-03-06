#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <vector>

static constexpr uint8_t flag_key[40]{
  0x46, 0x5c, 0x5c, 0x41, 0x68, 0x5c, 0x44, 0x39,
  0x11, 0x5f, 0x59, 0x11, 0x0e, 0x07, 0x66, 0x53,
  0x54, 0x10, 0x3c, 0x45, 0x07, 0x58, 0x44, 0x02,
  0x0e, 0x6f, 0x4c, 0x41, 0x0b, 0x59, 0x54, 0x6d,
  0x08, 0x5d, 0x41, 0x55, 0x3c, 0x50, 0x4b, 0x0f,
};

int main(int argc, char** argv) {
  char const* fname{argc >= 2 ? argv[1] : "field"};
  llvm::LLVMContext ctx;
  llvm::SMDiagnostic error;
  auto field_mod{llvm::parseIRFile(fname, error, ctx)};
  auto func{field_mod->getFunction(argc >= 3 ? argv[2] : "hello")};

  std::set<llvm::BasicBlock*> bb_visited{};
  std::list<llvm::BasicBlock*> bb_work_queue{};
  std::vector<llvm::BasicBlock*> bb_visit_trace{};

  bb_work_queue.push_back(&func->getEntryBlock());

  std::map<llvm::BasicBlock*, int32_t> bb_ids{};

  // ragnaRock
  int32_t counter{1};
  while (!bb_work_queue.empty()) {
    auto block{bb_work_queue.front()};
    bb_work_queue.pop_front();
    bb_visit_trace.push_back(block);
    bb_ids[block] = counter;
    counter++;
    bb_visited.insert(block);
    for (auto const& succ : llvm::successors(block)) {
      if (bb_visited.find(succ) == bb_visited.end()
          && std::find(bb_work_queue.begin(), bb_work_queue.end(), succ) == bb_work_queue.end()) {
        bb_work_queue.push_back(succ);
      }
    }
  }

  MD5_CTX md5_ctx;
  MD5_Init(&md5_ctx);
  SHA_CTX sha1_ctx;
  SHA1_Init(&sha1_ctx);

  for (auto const& block : bb_visit_trace) {
    MD5_Update(&md5_ctx, &bb_ids[block], 4);
    SHA1_Update(&sha1_ctx, &bb_ids[block], 4);

    auto succs{llvm::successors(block)};
    int64_t succs_size{succs.end() - succs.begin()};

    MD5_Update(&md5_ctx, &succs_size, 8);
    SHA1_Update(&sha1_ctx, &succs_size, 8);

    for (auto&& succ : succs) {
      MD5_Update(&md5_ctx, &bb_ids[succ], 4);
      SHA1_Update(&sha1_ctx, &bb_ids[succ], 4);
    }
  }

  uint8_t md5_hash[16];
  MD5_Final(md5_hash, &md5_ctx);
  uint8_t sha1_hash[20];
  SHA1_Final(sha1_hash, &sha1_ctx);

  std::stringstream hex_ss{};
  hex_ss << std::hex << std::setfill('0');

  for (auto c : md5_hash) {
    hex_ss << std::setw(2) << +c;
  }
  auto md5_hexhash{hex_ss.str()};
  hex_ss.str({});
  for (auto c : sha1_hash) {
    hex_ss << std::setw(2) << +c;
  }
  auto sha1_hexhash{hex_ss.str()};

  std::cout << "MD5:  " << md5_hexhash << std::endl;
  std::cout << "SHA1: " << sha1_hexhash << std::endl;

  if (md5_hexhash == "a3ee1e96ee111075ea6deaa0827f1b07") {
    std::cout << "flag: hackim18{";
    for (uint64_t i{0}; i < 40; i++) {
      std::cout << char(flag_key[i] ^ sha1_hexhash[i]);
    }
    std::cout << "}" << std::endl;
  }
}
