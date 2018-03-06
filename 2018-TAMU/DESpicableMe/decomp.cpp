#include <algorithm>
#include <bitset>
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iterator>
#include <string>
#include <tuple>
#include <vector>

// uncomment for decryption.
// #define DECRYPT

std::bitset<8> getKeybits(std::string key, int32_t& key_rot)
{
  char* buffer{reinterpret_cast<char*>(malloc(key.size() * 8))}; // rbp-0x48
  strcpy(buffer, key.c_str());
  std::vector<int32_t> vec{}; // rbp-0x30
  for (int32_t i{0}; uint64_t(i) < key.size(); i++) {
    // 0x00001d4c
    for (int32_t j{7}; j >= 0; j--) {
      // 0x00001d59
      vec.push_back(((buffer[i] << (7-j)) & 0x80) != 0);
    }
  }
  // 0x00001da9
  for (int32_t i{0}; i < key_rot; i++) {
    // 0x00001dbf
    int32_t vec_0{vec[0]}; // rbp-0x54
    for (int32_t j{1}; uint64_t(j) < vec.size(); j++) {
      // 0x00001df8
      vec[j-1] = vec[j];
    }
    // 0x00001e35
    vec[vec.size()-1] = vec_0;
  }
  // 0x00001e65
  std::bitset<8> ret{}; // rbp-0x50
  for (int32_t i{0}; i <= 7; i++) {
    // 0x00001e7d
    ret[7-i] = (vec[i] != 0);
  }
  // std::cerr << "ks: " << ret.to_string() << std::endl;
  return ret;
}

std::bitset<8> expand(std::bitset<6> bs)
{
  // 0x0000135a
  std::bitset<8> ret{};
  ret[0] = bs[0];
  ret[1] = bs[1];
  ret[2] = bs[3];
  ret[3] = bs[2];
  ret[4] = bs[3];
  ret[5] = bs[2];
  ret[6] = bs[4];
  ret[7] = bs[5];
  return ret;
}

std::bitset<6> sBox(std::bitset<4> bs_a, std::bitset<4> bs_b)
{
  // 0x000016c5
  uint32_t a_sub1[8] = {5,2,1,6,3,4,7,0}; // rbp-0xa0
  uint32_t a_sub0[8] = {1,4,6,2,0,7,5,3}; // rbp-0x80
  uint32_t b_sub1[8] = {4,0,6,5,7,1,3,2}; // rbp-0x60
  uint32_t b_sub0[8] = {5,3,0,7,6,2,1,4}; // rbp-0x40

  uint32_t a_msb{bs_a[3]}; // rbp-0xe8
  uint32_t b_msb{bs_b[3]}; // rbp-0xe4
  bs_a[3] = false;
  bs_b[3] = false;
  uint32_t a_int{uint32_t(bs_a.to_ulong())}; // rbp-0xe0
  uint32_t b_int{uint32_t(bs_b.to_ulong())}; // rbp-0xdc
  uint32_t tmp; // rbp-0xec
  if (a_msb == 0) {
    // 0x00001937
    tmp = a_sub1[a_int];
  } else {
    // 0x00001925
    tmp = a_sub0[a_int];
  }
  // 0x0000194a
  std::bitset<3> ret_hi{tmp}; // rbp-0xd8
  if (b_msb == 0) {
    // 0x0000197d
    tmp = b_sub1[b_int];
  } else {
    // 0x0000196b
    tmp = b_sub0[b_int];
  }
  // 0x0000198d
  std::bitset<3> ret_lo{tmp}; // rbp-0xd0
  std::bitset<6> ret{}; // rbp-0xc8
  ret[5] = ret_hi[2];
  ret[4] = ret_hi[1];
  ret[3] = ret_hi[0];
  ret[2] = ret_lo[2];
  ret[1] = ret_lo[1];
  ret[0] = ret_lo[0];
  return ret;
}

void doRounds(std::bitset<6> bs_a,
              std::bitset<6> bs_b,
              std::bitset<8> key_byte,
              std::string key,
              int32_t rounds,
              int32_t& key_rot,
              std::bitset<12>& enc_bits,
              int32_t key_adv)
{
  // std::cerr << "  doRounds: " << bs_a.to_string() << bs_b.to_string() << std::endl;
  // std::cerr << "    kr: " << key_rot << std::endl;
  // std::cerr << "    kb: " << key_byte.to_string() << std::endl;
  // 0x00001f21
  std::bitset<8> exp_b{expand(bs_b)}; // rbp-0xb0
  exp_b[7] = exp_b[7] != key_byte[7];
  exp_b[6] = exp_b[6] != key_byte[6];
  exp_b[5] = exp_b[5] != key_byte[5];
  exp_b[4] = exp_b[4] != key_byte[4];
  exp_b[3] = exp_b[3] != key_byte[3];
  exp_b[2] = exp_b[2] != key_byte[2];
  exp_b[1] = exp_b[1] != key_byte[1];
  exp_b[0] = exp_b[0] != key_byte[0];
  std::bitset<4> exp_b_hi{}; // rbp-0xa8
  std::bitset<4> exp_b_lo{}; // rbp-0xa0
  exp_b_hi[3] = exp_b[7];
  exp_b_hi[2] = exp_b[6];
  exp_b_hi[1] = exp_b[5];
  exp_b_hi[0] = exp_b[4];
  exp_b_lo[3] = exp_b[3];
  exp_b_lo[2] = exp_b[2];
  exp_b_lo[1] = exp_b[1];
  exp_b_lo[0] = exp_b[0];
  std::bitset<6> sbox_bits{sBox(exp_b_hi, exp_b_lo)}; // rbp-0x98
  sbox_bits[0] = bs_a[0] != sbox_bits[0];
  sbox_bits[1] = bs_a[1] != sbox_bits[1];
  sbox_bits[2] = bs_a[2] != sbox_bits[2];
  sbox_bits[3] = bs_a[3] != sbox_bits[3];
  sbox_bits[4] = bs_a[4] != sbox_bits[4];
  sbox_bits[5] = bs_a[5] != sbox_bits[5];
  rounds--;
  key_rot += key_adv;
  if (rounds == 0) {
    // 0x00002cc2
    enc_bits[11] = bs_b[5];
    enc_bits[10] = bs_b[4];
    enc_bits[ 9] = bs_b[3];
    enc_bits[ 8] = bs_b[2];
    enc_bits[ 7] = bs_b[1];
    enc_bits[ 6] = bs_b[0];
    enc_bits[ 5] = sbox_bits[5];
    enc_bits[ 4] = sbox_bits[4];
    enc_bits[ 3] = sbox_bits[3];
    enc_bits[ 2] = sbox_bits[2];
    enc_bits[ 1] = sbox_bits[1];
    enc_bits[ 0] = sbox_bits[0];
    // std::cerr << "       fin: " << enc_bits.to_string() << std::endl;
  } else {
    // 0x000031cb
    doRounds(bs_b, sbox_bits, getKeybits(key, key_rot), key, rounds, key_rot, enc_bits, key_adv);
  }
  // 0x00003296
}

std::string encrypt(std::string key, std::string msg, int32_t rounds)
{
  // 0x000032b0
  std::bitset<6> bs_a{}; // rbp-0xc8
  std::bitset<6> bs_b{}; // rbp-0xc0
  std::bitset<8> key_bits{}; // rbp-0xb8
  uint32_t local_d8h{0}; // rbp-0xd8
  uint32_t local_d4h{0}; // rbp-0xd4
  int32_t key_rot{0}; // rbp-0xdc

  char* buffer{reinterpret_cast<char*>(malloc(msg.size() * 8))}; // rbp-0xa8
  strcpy(buffer, msg.c_str());

  std::string ret{""}; // rbp-0xe8; RVO'd
  for (int32_t i{0}; uint64_t(i) < msg.size(); i++) {
    // 0x000033d6
    for (int32_t j{7}; j >= 0; j--) {
      // 0x000033ed
      if (local_d4h > 5) {
        // 0x0000347a
        bs_b[5 - local_d8h] = ((buffer[i] << (7-j)) & 0x80) != 0;
      } else {
        // 0x000033fa
        bs_a[5 - local_d8h] = ((buffer[i] << (7-j)) & 0x80) != 0;
      }
      local_d8h++;
      local_d4h++;
      // 0x000034ff
      if (local_d8h == 6) {
        // 0x00003513
        local_d8h = 0;
        if (local_d4h == 12) {
          // 0x0000352a
          key_bits = getKeybits(key, key_rot);
          std::bitset<12> enc_bits{}; // rbp-0xb0
          doRounds(bs_a, bs_b, key_bits, key, rounds, key_rot, enc_bits, 1);
          ret += " " + enc_bits.to_string().substr(0,6);
          bs_a[5] = enc_bits[5];
          bs_a[4] = enc_bits[4];
          bs_a[3] = enc_bits[3];
          bs_a[2] = enc_bits[2];
          bs_a[1] = enc_bits[1];
          bs_a[0] = enc_bits[0];
          local_d4h = 6;
        }
      }
    }
    // 0x0000395d
  }
  // std::cerr << bs_a.to_string() << std::endl;
  // 0x000039f8
  return ret;
}

#ifdef DECRYPT
void decrypt(std::string key, std::string ct, int32_t rounds, bool force_print, bool dump_bits)
{
  ct.push_back(' ');
  assert(ct.size() % 7 == 0);

  std::vector<std::bitset<6>> ct_hblocks{};
  ct_hblocks.reserve(ct.size()/7);
  for (size_t i{0}; i < ct.size(); i+=7) {
    assert(ct[i+6] == ' ');
    ct_hblocks.emplace_back(std::bitset<6>{ct.substr(i,6)});
  }

  size_t pt_bits_size{(ct_hblocks.size()+1)*6};
  assert(pt_bits_size % 8 == 0);

  std::vector<std::bitset<6>> r_ct_hblocks{ct_hblocks.crbegin(), ct_hblocks.crend()};

  // brute-force the first-half block
  for (size_t i{0}; i < 64; i++) {
    std::bitset<6> bs_a{i};

    // decrypt <=> encrypt with reverse key schedule
    int32_t key_rot{int32_t(ct_hblocks.size()*rounds) - 1};

    std::vector<uint8_t> r_pt_bits{};
    for (auto const& hblock : r_ct_hblocks) {
      std::bitset<12> dec_bits;
      doRounds(bs_a, hblock, getKeybits(key, key_rot), key, rounds, key_rot, dec_bits, -1);
      r_pt_bits.emplace_back(dec_bits[ 6]);
      r_pt_bits.emplace_back(dec_bits[ 7]);
      r_pt_bits.emplace_back(dec_bits[ 8]);
      r_pt_bits.emplace_back(dec_bits[ 9]);
      r_pt_bits.emplace_back(dec_bits[10]);
      r_pt_bits.emplace_back(dec_bits[11]);
      bs_a[5] = dec_bits[ 5];
      bs_a[4] = dec_bits[ 4];
      bs_a[3] = dec_bits[ 3];
      bs_a[2] = dec_bits[ 2];
      bs_a[1] = dec_bits[ 1];
      bs_a[0] = dec_bits[ 0];
    }
    r_pt_bits.emplace_back(bs_a[ 0]);
    r_pt_bits.emplace_back(bs_a[ 1]);
    r_pt_bits.emplace_back(bs_a[ 2]);
    r_pt_bits.emplace_back(bs_a[ 3]);
    r_pt_bits.emplace_back(bs_a[ 4]);
    r_pt_bits.emplace_back(bs_a[ 5]);

    std::vector<uint8_t> pt_bits{r_pt_bits.crbegin(), r_pt_bits.crend()};
    if (dump_bits) {
      std::cout << "bits: ";
      std::copy(pt_bits.cbegin(), pt_bits.cend(), std::ostream_iterator<int>{std::cout});
      std::cout << std::endl;
    }

    std::string pt_bytes{};
    for (size_t i{0}; i < pt_bits_size/8; i++) {
      uint8_t c{0};
      c |= pt_bits[i*8 + 0] << 7;
      c |= pt_bits[i*8 + 1] << 6;
      c |= pt_bits[i*8 + 2] << 5;
      c |= pt_bits[i*8 + 3] << 4;
      c |= pt_bits[i*8 + 4] << 3;
      c |= pt_bits[i*8 + 5] << 2;
      c |= pt_bits[i*8 + 6] << 1;
      c |= pt_bits[i*8 + 7] << 0;
      pt_bytes.push_back(c);
    }

    // only print printable bytes
    if (force_print || std::all_of(pt_bytes.cbegin(), pt_bytes.cend(), [](char c){ return 0x20 <= c; })){
      std::cout << "candidate: " << pt_bytes << std::endl;
    }
  }
}
#endif

#ifndef DECRYPT
// original
int main() {
  int32_t rounds{2};
  std::string key{"Mu"};
  std::string msg{"MiN0n!"};
  // ... arg parsing ...
  // ... check that msg.size()*8 % 12 == 0 ...
  printf("Encrypted Bits: %s\n", encrypt(key, msg, rounds).c_str());
}
#endif

#ifdef DECRYPT
int main(int argc, char** argv)
{
  if (argc != 6) {
    std::cerr << "Usage: " << argv[0] << " <key> <msg> <rounds> <force-print> <dump-bits>" << std::endl;
    exit(1);
  }
  decrypt(argv[1], argv[2], std::stoi(argv[3]), std::stoi(argv[4]), std::stoi(argv[5]));
}
#endif
