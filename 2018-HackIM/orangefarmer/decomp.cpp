#include <llvm/ADT/StringRef.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Module.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <iostream>
#include <list>
#include <map>
#include <set>

namespace NULLCON_2018 {
  class MangoGuy {
  public:
    int32_t id;
    std::vector<int32_t> succs;

    static MangoGuy* bammer1()
    {
      int32_t tmp1;
      std::cin >> tmp1;
      if (tmp1 < 0) {
        return nullptr;
      }
      MangoGuy* ret{new MangoGuy{}};
      ret->id = tmp1;
      std::cin >> tmp1;
      if (!(0 < tmp1 && tmp1 <= 46)) {
        if (ret != nullptr) {
          delete ret;
        }
        return nullptr;
      }
      for (int32_t i{0}; i < tmp1; i++) {
        int32_t tmp2;
        std::cin >> tmp2;
        ret->succs.push_back(tmp2);
      }
      return ret;
    }
  };

  class OrangeFarming : public llvm::ModulePass {
  private:
    static constexpr uint8_t flag_key[40]{
      0x46, 0x5c, 0x5c, 0x41, 0x68, 0x5c, 0x44, 0x39,
      0x11, 0x5f, 0x59, 0x11, 0x0e, 0x07, 0x66, 0x53,
      0x54, 0x10, 0x3c, 0x45, 0x07, 0x58, 0x44, 0x02,
      0x0e, 0x6f, 0x4c, 0x41, 0x0b, 0x59, 0x54, 0x6d,
      0x08, 0x5d, 0x41, 0x55, 0x3c, 0x50, 0x4b, 0x0f,
    };
  public:
    static char ID;

    OrangeFarming()
      : llvm::ModulePass{ID}
    {}

    bool runOnModule(llvm::Module& ll_mod) override
    {
      // 0x00038932
      std::map<int, MangoGuy*> guy_map{}; // rbp-0x200
      guy_map.clear();
      MangoGuy* entry_guy{nullptr}; // rbp-0x2a8

      int32_t guy_count; // rbp-0x2c4
      std::cin >> guy_count;
      if (guy_count < 0 || guy_count > 46) {
        // 0x000389b2
        return false;
      }

      // 0x000389bc
      for (int32_t i{0}; i < guy_count; i++) {
        // 0x000389d8
        MangoGuy* new_guy{MangoGuy::bammer1()}; // rbp-0x278
        if (new_guy != nullptr && !(guy_map.find(new_guy->id) == guy_map.end())) {
          // 0x00038a45
          guy_map[new_guy->id] = new_guy;
          if (entry_guy == nullptr) {
            entry_guy = new_guy;
          }
        }
      }
      // 0x00038a91
      if (guy_map.empty() || entry_guy == nullptr) {
        // 0x00038ac0
        return false;
      }
      // 0x00038aca
      for (auto& fn : ll_mod.getFunctionList()) {
        // 0x00038b27
        if (isFarmHarvestable(&fn)) {
          // 0x00038b5e
          if (fn.getBasicBlockList().size() != guy_map.size()) {
            // 0x00038b91
            return false;
          }
          // 0x00038b9b
          std::set<llvm::BasicBlock*> bb_visited{};
          std::set<MangoGuy*> guy_visited{};
          MD5_CTX md5_ctx;
          MD5_Init(&md5_ctx);
          SHA_CTX sha1_ctx;
          SHA1_Init(&sha1_ctx);
          bb_visited.clear();
          guy_visited.clear();

          llvm::BasicBlock& entry_bb{fn.getEntryBlock()};
          std::list<llvm::BasicBlock*> bb_work_queue{};
          bb_work_queue.clear();
          bb_work_queue.push_back(&entry_bb);
          std::list<MangoGuy*> guy_work_queue{};
          guy_work_queue.clear();
          guy_work_queue.push_back(entry_guy);

          std::vector<MangoGuy*> guy_visit_trace{};
          guy_visit_trace.clear();

          if (ragnaRock(bb_work_queue,
                        guy_work_queue,
                        bb_visited,
                        guy_visited,
                        guy_map,
                        1,
                        fn.getBasicBlockList().size(),
                        guy_visit_trace)) {
            // 0x00038cff
            for (int32_t j{0}; uint64_t(j) < guy_visit_trace.size(); j++) {
              // 0x00038d2f
              MangoGuy& guy{*guy_visit_trace[j]}; // rbp-0x268
              MD5_Update(&md5_ctx, &guy.id, 4);
              uint64_t guy_vec_size{guy.succs.size()}; // rbp-0x298
              MD5_Update(&md5_ctx, &guy_vec_size, 8);
              for (int32_t k{0}; uint64_t(k) < guy.succs.size(); k++) {
                // 0x00038dda
                MD5_Update(&md5_ctx, &guy.succs[k], 4);
              }
              // 0x00038e1b
              SHA1_Update(&sha1_ctx, &guy.id, 4);
              SHA1_Update(&sha1_ctx, &guy_vec_size, 8);
              for (int32_t k{0}; uint64_t(k) < guy.succs.size(); k++) {
                // 0x00038e87
                SHA1_Update(&sha1_ctx, &guy.succs[k], 4);
              }
            }
            // 0x00038ed4
            uint8_t md5_hash[16]; // rbp-0xb0
            MD5_Final(md5_hash, &md5_ctx);
            uint8_t sha1_hash[20]; // rbp-0xa0
            SHA1_Final(sha1_hash, &sha1_ctx);
            char md5_hexhash[32]; // rbp-0x80
            for (uint64_t j{0}; j < 16; j++) {
              // 0x00038f1b
              sprintf(&md5_hexhash[j*2], "%02x", md5_hash[j]);
            }
            // 0x00038f64
            char sha1_hexhash[40]; // rbp-0x50
            for (uint64_t j{0}; j < 20; j++) {
              // 0x00038f79
              sprintf(&sha1_hexhash[j*2], "%02x", sha1_hash[j]);
            }
            // 0x00038fc2
            if (strcmp(md5_hexhash, "a3ee1e96ee111075ea6deaa0827f1b07") == 0) {
              // 0x00038fdd
              std::cout << "hackim18{";
              for (uint64_t j{0}; j < 40; j++) {
                // 0x00039008
                char c{char(flag_key[j] ^ sha1_hexhash[j])};
                std::cout << c;
              }
              // 0x00039057
              std::cout << "}" << std::endl;
            }
          }
        }
      }
      // 0x000390e6
      return false;
    }

    bool isFarmHarvestable(llvm::Function* func)
    {
      // 0x0003802e
      if (func->isDeclaration() || !func->hasName()) {
        // 0x000380e9
        return false;
      }
      // 0x00038083
      return 4 < func->getName().size() && func->getName().size() <= 5;
      // func->getName().size() == 5
    }

    bool ragnaRock(std::list<llvm::BasicBlock*>& bb_work_queue,
                   std::list<NULLCON_2018::MangoGuy*>& guy_work_queue,
                   std::set<llvm::BasicBlock*>& bb_visited,
                   std::set<NULLCON_2018::MangoGuy*>& guy_visited,
                   std::map<int, NULLCON_2018::MangoGuy*>& guy_map,
                   int32_t counter,
                   int32_t bb_count,
                   std::vector<NULLCON_2018::MangoGuy*>& guy_visit_trace)
    {
      // 0x000381b0
      if (bb_work_queue.size() != guy_work_queue.size()) {
        // 0x0003884f
        return false;
      }
      // 0x00038237
      if (bb_work_queue.empty()) {
        // 0x00038848
        return true;
      }
      // 0x00038251
      llvm::BasicBlock* front_block{bb_work_queue.front()};
      bb_work_queue.pop_front();
      MangoGuy* front_guy{guy_work_queue.front()};
      guy_work_queue.pop_front();
      guy_visit_trace.push_back(front_guy);
      if (front_guy->id < counter || front_guy->id > bb_count) {
        // 0x00038324
        return false;
      }
      // front_guy->id \in [counter, bb_count]
      // 0x000382c7
      counter++;
      bb_visited.insert(front_block);
      guy_visited.insert(front_guy);

      std::vector<llvm::BasicBlock*> bb_succs{};
      bb_succs.clear();
      fetchOranges(front_block, bb_succs);
      if (bb_succs.size() != front_guy->succs.size()) {
        // 0x000387e9
        return false;
      }

      // 0x0003835b
      for (int32_t i{0}; uint64_t(i) < bb_succs.size(); i++) {
        // 0x00038388
        MangoGuy* guy_succ{bammer(guy_map, front_guy->succs[i])}; // rbp-0x58
        if (guy_succ == nullptr) {
          // 0x000383cb
          return false;
        }

        // 0x000383d5
        if (bb_visited.find(bb_succs[i]) == bb_visited.end()) {
          // 0x00038496
          if (guy_visited.find(guy_succ) != guy_visited.end()) {
            // 0x000384e6
            return false;
          }
        } else {
          // 0x0003843c
          if (guy_visited.find(guy_succ) == guy_visited.end()) {
            // 0x0003848c
            return false;
          }
        }
        // bb_succs[i] \in bb_visited <==> guy_succ \in guy_visited
        // 0x000384f0
        if (std::find(bb_work_queue.begin(), bb_work_queue.end(), bb_succs[i]) == bb_work_queue.end()) {
          // 0x00038574
          if (std::find(guy_work_queue.begin(), guy_work_queue.end(), guy_succ) != guy_work_queue.end()) {
            // 0x000385e8
            return false;
          }
        } else {
          // 0x000385f2
          if (std::find(guy_work_queue.begin(), guy_work_queue.end(), guy_succ) == guy_work_queue.end()) {
            // 0x00038662
            return false;
          }
        }
        // bb_succs[i] \in bb_work_queue <==> guy_succ \in guy_work_queue

        // 0x0003866c
        if (bb_visited.find(bb_succs[i]) == bb_visited.end()
            && std::find(bb_work_queue.begin(), bb_work_queue.end(), bb_succs[i]) == bb_work_queue.end()) {
            // 0x0003879a
          bb_work_queue.push_back(bb_succs[i]);
          guy_work_queue.push_back(guy_succ);
        }
      } // end for over bb_succs
      // 0x000387f0
      return ragnaRock(bb_work_queue, guy_work_queue, bb_visited, guy_visited, guy_map, counter, bb_count, guy_visit_trace);
    }

    /** bb_succs <- succ(block) */
    static void fetchOranges(llvm::BasicBlock* block, std::vector<llvm::BasicBlock*>& bb_succs)
    {
      bb_succs.clear();
      auto bb_sb{llvm::succ_begin(block)};
      auto bb_se{llvm::succ_end(block)};
      while (bb_sb != bb_se) {
        // 0x000416b4
        bb_succs.push_back(*bb_sb);
        ++bb_sb;
      }
    }

    /** get or null */
    MangoGuy* bammer(std::map<int, NULLCON_2018::MangoGuy*>& guy_map, int guy_id)
    {
      if (guy_map.find(guy_id) != guy_map.end()) {
        return guy_map[guy_id];
      }
      return nullptr;
    }
  };
  static llvm::RegisterPass<OrangeFarming> idkwhattocallthis{"try-this", "Magic!", false, true};
}
