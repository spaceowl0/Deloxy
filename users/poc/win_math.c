/* Floating point on Windows: libm, printf/scanf %f %e %g, strtod/atof. Output is compared against the same source built natively. */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define LOAD(n) static double (*n##_p)(double); 
typedef double (*F1)(double); typedef double (*F2)(double, double); typedef double (*FI)(double, int); typedef double (*FS)(const char *, char **);
static HMODULE M;
#define G1(n) F1 n##_ = (F1)GetProcAddress(M, #n)
#else
#include <dlfcn.h>
#endif
int main(int argc, char **argv) {
  volatile double x = 0.7853981633974483, y = 2.5, z = -3.75, big = 1234567.891, tiny = 0.000123456;
  volatile float xf = 1.5f, yf = 2.25f;
  printf("sin=%.12g cos=%.12g tan=%.12g\n", sin(x), cos(x), tan(x));
  printf("asin=%.12g acos=%.12g atan=%.12g atan2=%.12g\n", asin(0.5), acos(0.5), atan(y), atan2(y, z));
  printf("exp=%.12g log=%.12g log10=%.12g log2=%.12g\n", exp(y), log(y), log10(big), log2(big));
  printf("pow=%.12g sqrt=%.12g cbrt=%.12g hypot=%.12g\n", pow(y, 3.5), sqrt(y), cbrt(z), hypot(3.0, 4.0));
  printf("floor=%.1f ceil=%.1f trunc=%.1f round=%.1f fmod=%.6f fabs=%.2f\n", floor(z), ceil(z), trunc(z), round(y), fmod(big, y), fabs(z));
  printf("sinh=%.10g cosh=%.10g tanh=%.10g\n", sinh(y), cosh(y), tanh(y));
  printf("f32: sinf=%.7g sqrtf=%.7g powf=%.7g fabsf=%.3f\n", sinf(xf), sqrtf(yf), powf(xf, yf), fabsf(-yf));
  printf("fmt: [%f] [%.2f] [%10.3f] [%-10.1f] [%+.1f] [%010.4f]\n", y, big, z, y, y, z);
  printf("fmt: [%e] [%.3e] [%E] [%g] [%g] [%g] [%G]\n", big, tiny, tiny, big, tiny, 100000.0, 1e-10);
  printf("fmt: [%g] [%g] [%.3g] [%#g] [%.0f] [%5.1f%%]\n", 0.5, 1e20, 3.14159, 2.5, 2.5, 99.44);
  printf("special: [%f] [%f]\n", INFINITY, -INFINITY);
  double iptr; double frac = modf(z, &iptr); int ex; double m = frexp(big, &ex);
  printf("modf=%.2f/%.2f frexp=%.6f/%d ldexp=%.3f\n", frac, iptr, m, ex, ldexp(1.5, 4));
  printf("strtod=%.6f atof=%.4f", strtod("  3.14159abc", NULL), atof("-2.5e2"));
  char *end; double v = strtod("12.5xyz", &end); printf(" end='%s' v=%.1f\n", end, v);
  double a = 0, b = 0; float c = 0; int n = sscanf("1.25 -7.5e1 3.5", "%lf %lf %f", &a, &b, &c);
  printf("sscanf: n=%d %.3f %.3f %.3f\n", n, a, b, c);
  printf("isnan=%d finite=%d\n", !!isnan(nan("")), !!isfinite(y));
  double acc = 0; for (int i = 1; i <= 1000; i++) acc += 1.0 / (i * (double)i);
  printf("sum=%.10f pi2/6=%.10f\n", acc, M_PI * M_PI / 6);

#ifdef _WIN32
  M = GetModuleHandleA("msvcrt.dll");
  F1 s_ = (F1)GetProcAddress(M, "sin"), e_ = (F1)GetProcAddress(M, "exp"), l_ = (F1)GetProcAddress(M, "log"), q_ = (F1)GetProcAddress(M, "sqrt"), f_ = (F1)GetProcAddress(M, "floor"), a_ = (F1)GetProcAddress(M, "atan");
  F2 p_ = (F2)GetProcAddress(M, "pow"), t_ = (F2)GetProcAddress(M, "atan2"), m_ = (F2)GetProcAddress(M, "fmod");
  FI ld_ = (FI)GetProcAddress(M, "ldexp"); FS sd_ = (FS)GetProcAddress(M, "strtod");
  printf("dyn: %s\n", (s_ && e_ && l_ && q_ && f_ && a_ && p_ && t_ && m_ && ld_ && sd_) ? "resolved" : "MISSING");
  printf("dyn: sin=%.12g exp=%.12g log=%.12g sqrt=%.12g floor=%.1f atan=%.12g\n", s_(x), e_(y), l_(y), q_(y), f_(z), a_(y));
  printf("dyn: pow=%.12g atan2=%.12g fmod=%.6f ldexp=%.3f strtod=%.4f\n", p_(y, 3.5), t_(y, z), m_(big, y), ld_(1.5, 4), sd_("2.75", NULL));
#else
  printf("dyn: resolved\n");
  printf("dyn: sin=%.12g exp=%.12g log=%.12g sqrt=%.12g floor=%.1f atan=%.12g\n", sin(x), exp(y), log(y), sqrt(y), floor(z), atan(y));
  printf("dyn: pow=%.12g atan2=%.12g fmod=%.6f ldexp=%.3f strtod=%.4f\n", pow(y, 3.5), atan2(y, z), fmod(big, y), ldexp(1.5, 4), strtod("2.75", NULL));
#endif
  return 0;
}
