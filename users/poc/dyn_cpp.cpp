#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <chrono>
#include <memory>
int main() {
  std::vector<int> v = {5, 3, 9, 1, 7}; std::sort(v.begin(), v.end());
  std::map<std::string, int> m; for (int x : v) m["k" + std::to_string(x)] = x * x;
  std::cout << "cpp: sorted"; for (int x : v) std::cout << ' ' << x; std::cout << " map=" << m.size() << " k9=" << m["k9"] << std::endl;
  try { throw std::runtime_error("boom"); } catch (const std::exception &e) { std::cout << "cpp: caught " << e.what() << std::endl; }
  std::mutex mu; long total = 0; std::vector<std::thread> th;
  for (int i = 0; i < 4; i++) th.emplace_back([&, i] { for (int k = 0; k < 1000; k++) { std::lock_guard<std::mutex> g(mu); total += i; } });
  for (auto &t : th) t.join();
  std::cout << "cpp: threads total=" << total << std::endl;
  auto sp = std::make_shared<std::string>("shared"); std::cout << "cpp: " << *sp << " use=" << sp.use_count() << std::endl;
  auto t0 = std::chrono::steady_clock::now(); std::this_thread::sleep_for(std::chrono::milliseconds(50));
  std::cout << "cpp: slept " << (std::chrono::steady_clock::now() - t0 >= std::chrono::milliseconds(40)) << std::endl;
  return 0;
}
