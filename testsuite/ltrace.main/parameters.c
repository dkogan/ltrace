/* Ltrace Test : parameters.c.
   Objectives  : Verify that Ltrace can handle all the different
   parameter types

   This file was written by Steve Fink <sphink@gmail.com>. */

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

void func_intptr(int *i);
void func_intptr_ret(int *i);
int func_strlen(char*);
void func_strfixed(char*);
void func_ppp(int***);
void func_stringp(char**);
void func_short(short, short);
void func_ushort(unsigned short, unsigned short);
float func_float(float, float);
double func_double(double, double);
void func_arrayi(int*, int);
void func_arrayf(float*, int);
void func_struct(void*);

typedef enum {
  RED,
  GREEN,
  BLUE,
  CHARTREUSE,
  PETUNIA
} color_t;
void func_enum(color_t);
void func_typedef(color_t);

void func_work(char *x);
void func_call(char *x, char *y, void (*cb)(char *));

void
call_func_work (char *x)
{
	func_work(x);
}

int
main ()
{
  int x = 17;
  int *xP, **xPP;
  char buf[200];
  char *s;
  int *ai;
  float *af;

  func_intptr(&x);

  func_intptr_ret(&x);

  func_string("zero\0xxxxxxxxxxxxxx");
  func_strlen(buf);

  extern int func_arg0(char *);
  func_arg0(buf);

  printf("%s\n", buf);

  func_strfixed(buf);
  printf("%s\n", buf);

  x = 80;
  xP = &x;
  xPP = &xP;
  func_ppp(&xPP);

  s = (char*) malloc(100);
  strcpy(s, "Dude");
  func_stringp(&s);

  func_enum(BLUE);

  func_short(-8, -9);
  func_ushort(33, 34);
  float f = func_float(3.4, -3.4);
  double d = func_double(3.4, -3.4);

  func_typedef(BLUE);

  ai = (int*) calloc(sizeof(int), 8);
  for (x = 0; x < 8; x++)
    ai[x] = 10 + x;
  func_arrayi(ai, 8);
  func_arrayi(ai, 2);

  af = (float*) calloc(sizeof(float), 8);
  for (x = 0; x < 8; x++)
    af[x] = 10.1 + x;
  func_arrayf(af, 8);
  func_arrayf(af, 2);

  {
    struct {
      int simple;
      int alen;
      int slen;
      struct { int a; int b; }* array;
      struct { int a; int b; } seq[3];
      char* str;
    } x;

    x.simple = 89;

    x.alen = 2;
    x.array = malloc(800);
    x.array[0].a = 1;
    x.array[0].b = 10;
    x.array[1].a = 3;
    x.array[1].b = 30;

    x.seq[0].a = 4;
    x.seq[0].b = 40;
    x.seq[1].a = 5;
    x.seq[1].b = 50;
    x.seq[2].a = 6;
    x.seq[2].b = 60;

    x.slen = 3;
    x.str = "123junk";

    func_struct(&x);
  }

  {
    char x[10] = {};
    char y[10] = {};
    func_call(x, y, call_func_work);
  }

  struct S2 {
    float f;
    char a;
    char b;
  };
  struct S3 {
    char a[6];
    float f;
  };
  struct S2 func_struct_2(int, struct S3 s3, double d);
  func_struct_2(17, (struct S3){ "ABCDE", 0.25 }, 0.5);

  struct S4 {
    long a;
    long b;
    long c;
    long d;
  };
  struct S4 func_struct_large(struct S4 a, struct S4 b);
  func_struct_large((struct S4){ 1, 2, 3, 4 }, (struct S4){ 5, 6, 7, 8 });

  struct S5 {
    char a;
    char b;
    long c;
    long d;
  };
  struct S5 func_struct_large2(struct S5 a, struct S5 b);
  func_struct_large2((struct S5){ '0', '1', 3, 4 }, (struct S5){ '2', '3', 7, 8 });

  struct S6 {
    long a;
    long b;
    char c;
    char d;
  };
  struct S6 func_struct_large3(struct S6 a, struct S6 b);
  func_struct_large3((struct S6){ 3, 4, '0', '1' }, (struct S6){ 7, 8 ,'2', '3' });

  void func_many_args(int a, int b, long c, double d, char e, int f, float g,
		      char h, int i, double j, int k, double l, char m, int n,
		      short o, int p, char q, float r, float s, double t,
		      long u, float v, float w, float x, float y);
  func_many_args(1, 2, 3, 4.0, '5', 6, 7.0,
		 '8', 9, 10.0, 11, 12.0, 'A', 14,
		 15, 16, 'B', 18.0, 19.0, 20.0,
		 21, 22.0, 23.0, 24.0, 25.0);

  void func_printf(char *format, ...);
  func_printf("sotnuh %d %ld %g %c\n", 5, 6L, 1.5, 'X');
  func_printf("sotnuh1 %d %ld %hd\n", 5, 6L, (short)7);
  func_printf("sotnuh2 %s %10s %10s\n", "a string", "a trimmed string", "short");
  func_printf("many_args"
	 "%d %d %ld %g %c %d %g "
	 "%c %d %g %d %g %c %d "
	 "%hd %d %c %g %g %g "
	 "%ld %g %g %g %g",
	 1, 2, 3L, 4.0, '5', 6, 7.0,
	 '8', 9, 10.0, 11, 12.0, 'A', 14,
	 (short)15, 16, 'B', 18.0, 19.0, 20.0,
	 21L, 22.0, 23.0, 24.0, 25.0);

  func_printf("sotnuh3 %*s\n", 4, "a trimmed string");

  void func_sprintf(char *str, char *format, ...);
  func_sprintf(NULL, "test %d %d %d %d\n", 1, 2, 3, 4);

  void func_lens(int, long, short, long);
  func_lens(22, 23, 24, 25);

  int func_bool(int a, int b);
  func_bool(1, 10);
  func_bool(2, 0);

  void func_hide(int a, int b, int c, int d, int e, int f, int g, int h);
  func_hide(1, 2, 3, 4, 5, 6, 7, 8);

  struct func_hide_struct {
	  int a; int b; int c; int d; int e; int f; int g; int h;
  };
  void func_hide_struct(struct func_hide_struct hs);
  func_hide_struct((struct func_hide_struct){1, 2, 3, 4, 5, 6, 7, 8});

  enum ab { A, B };
  long *func_short_enums(short abs[]);
  func_short_enums((short[]){ A, B, A, A });

  long func_negative_enum(short a, unsigned short b, int c, unsigned d,
                         long e, unsigned long f);
  func_negative_enum(-1, -1, -1, -1, -1, -1);

  void func_charp_string(char *p);
  func_charp_string("null-terminated string");

  struct dbl_eqv1 { double d; };
  struct dbl_eqv2 { struct dbl_eqv1 d; };
  struct dbl_eqv3 { struct dbl_eqv2 d; };
  struct dbl_eqv4 { struct dbl_eqv3 d; };

  struct flt_eqv1 { float d; };
  struct flt_eqv2 { struct flt_eqv1 d; };
  struct flt_eqv3 { struct flt_eqv2 d; };
  struct flt_eqv4 { struct flt_eqv3 d; };

  struct dbl_eqv1 func_dbl_eqv(struct dbl_eqv1 a, struct dbl_eqv2 b,
			       struct dbl_eqv3 c, struct dbl_eqv4 d);
  func_dbl_eqv((struct dbl_eqv1){ 2.5 },
	       (struct dbl_eqv2){ { 1.5 } },
	       (struct dbl_eqv3){ { { 0.5 } } },
	       (struct dbl_eqv4){ { { { -0.5 } } } });

  struct flt_eqv1 func_flt_eqv(struct flt_eqv1 a, struct flt_eqv2 b,
			       struct flt_eqv3 c, struct flt_eqv4 d);
  func_flt_eqv((struct flt_eqv1){ 2.5 },
	       (struct flt_eqv2){ { 1.5 } },
	       (struct flt_eqv3){ { { 0.5 } } },
	       (struct flt_eqv4){ { { { -0.5 } } } });

  struct struct_empty {};
  struct struct_empty func_struct_empty(struct struct_empty e);
  func_struct_empty((struct struct_empty) {});

  struct struct_size1 { char a; };
  struct struct_size1 func_struct_size1(struct struct_size1 e);
  func_struct_size1((struct struct_size1){ '5' });

  struct struct_size2 { short a; };
  struct struct_size2 func_struct_size2(struct struct_size2 e);
  func_struct_size2((struct struct_size2){ 5 });

  struct struct_size4 { int a; };
  struct struct_size4 func_struct_size4(struct struct_size4 e);
  func_struct_size4((struct struct_size4){ 5 });

  struct struct_size8 { int a; int b; };
  struct struct_size8 func_struct_size8(struct struct_size8 e);
  func_struct_size8((struct struct_size8){ 5, 6 });

  /* Test Itanium Homogeneous Floating-point Aggregates.   */

  struct struct_hfa_f2 { float a; struct flt_eqv1 b; };
  struct struct_hfa_f2 func_hfa_f2(struct struct_hfa_f2 e);
  func_hfa_f2((struct struct_hfa_f2){ 1, { 2 } });

  struct struct_hfa_f3 { float a; struct struct_hfa_f2 b; };
  struct struct_hfa_f3 func_hfa_f3(struct struct_hfa_f3 e);
  func_hfa_f3((struct struct_hfa_f3){ 3, { 1, { 2 } } });

  struct struct_hfa_f4 { float a; struct struct_hfa_f3 b; };
  struct struct_hfa_f4 func_hfa_f4(struct struct_hfa_f4 e);
  func_hfa_f4((struct struct_hfa_f4){ 4, { 3, { 1, { 2 } } } });

  struct struct_hfa_f5 { float a; struct struct_hfa_f4 b; };
  struct struct_hfa_f5 func_hfa_f5(struct struct_hfa_f5 e);
  func_hfa_f5((struct struct_hfa_f5){ 5, { 4, { 3, { 1, { 2 } } } } });

  struct struct_hfa_f6 { float a; struct struct_hfa_f5 b; };
  struct struct_hfa_f6 func_hfa_f6(struct struct_hfa_f6 e);
  func_hfa_f6((struct struct_hfa_f6){ 6, { 5, { 4, { 3, { 1, { 2 } } } } } });

  struct struct_hfa_f7 { float a; struct struct_hfa_f6 b; };
  struct struct_hfa_f7 func_hfa_f7(struct struct_hfa_f7 e);
  func_hfa_f7((struct struct_hfa_f7){ 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } });

  struct struct_hfa_f8 { float a; struct struct_hfa_f7 b; };
  struct struct_hfa_f8 func_hfa_f8(struct struct_hfa_f8 e);
  func_hfa_f8((struct struct_hfa_f8){ 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } });

  struct struct_hfa_f9 { float a; struct struct_hfa_f8 b; };
  struct struct_hfa_f9 func_hfa_f9(struct struct_hfa_f9 e);
  func_hfa_f9((struct struct_hfa_f9){ 9, { 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } } });

  struct struct_hfa_f10 { float a; struct struct_hfa_f9 b; };
  struct struct_hfa_f10 func_hfa_f10(struct struct_hfa_f10 e);
  func_hfa_f10((struct struct_hfa_f10){ 10, { 9, { 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } } } });

  struct struct_hfa_f11 { float a; struct struct_hfa_f10 b; };
  struct struct_hfa_f11 func_hfa_f11(struct struct_hfa_f11 e);
  func_hfa_f11((struct struct_hfa_f11){ 11, { 10, { 9, { 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } } } } });

  struct struct_hfa_f12 { float a; struct struct_hfa_f11 b; };
  struct struct_hfa_f12 func_hfa_f12(struct struct_hfa_f12 e);
  func_hfa_f12((struct struct_hfa_f12){ 12, { 11, { 10, { 9, { 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } } } } } });


  struct struct_hfa_d2 { double a; struct dbl_eqv1 b; };
  struct struct_hfa_d2 func_hfa_d2(struct struct_hfa_d2 e);
  func_hfa_d2((struct struct_hfa_d2){ 1, { 2 } });

  struct struct_hfa_d3 { double a; struct struct_hfa_d2 b; };
  struct struct_hfa_d3 func_hfa_d3(struct struct_hfa_d3 e);
  func_hfa_d3((struct struct_hfa_d3){ 3, { 1, { 2 } } });

  struct struct_hfa_d4 { double a; struct struct_hfa_d3 b; };
  struct struct_hfa_d4 func_hfa_d4(struct struct_hfa_d4 e);
  func_hfa_d4((struct struct_hfa_d4){ 4, { 3, { 1, { 2 } } } });

  struct struct_hfa_d5 { double a; struct struct_hfa_d4 b; };
  struct struct_hfa_d5 func_hfa_d5(struct struct_hfa_d5 e);
  func_hfa_d5((struct struct_hfa_d5){ 5, { 4, { 3, { 1, { 2 } } } } });

  struct struct_hfa_d6 { double a; struct struct_hfa_d5 b; };
  struct struct_hfa_d6 func_hfa_d6(struct struct_hfa_d6 e);
  func_hfa_d6((struct struct_hfa_d6){ 6, { 5, { 4, { 3, { 1, { 2 } } } } } });

  struct struct_hfa_d7 { double a; struct struct_hfa_d6 b; };
  struct struct_hfa_d7 func_hfa_d7(struct struct_hfa_d7 e);
  func_hfa_d7((struct struct_hfa_d7){ 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } });

  struct struct_hfa_d8 { double a; struct struct_hfa_d7 b; };
  struct struct_hfa_d8 func_hfa_d8(struct struct_hfa_d8 e);
  func_hfa_d8((struct struct_hfa_d8){ 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } });

  struct struct_hfa_d9 { double a; struct struct_hfa_d8 b; };
  struct struct_hfa_d9 func_hfa_d9(struct struct_hfa_d9 e);
  func_hfa_d9((struct struct_hfa_d9){ 9, { 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } } });

  struct struct_hfa_d10 { double a; struct struct_hfa_d9 b; };
  struct struct_hfa_d10 func_hfa_d10(struct struct_hfa_d10 e);
  func_hfa_d10((struct struct_hfa_d10){ 10, { 9, { 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } } } });

  struct struct_hfa_d11 { double a; struct struct_hfa_d10 b; };
  struct struct_hfa_d11 func_hfa_d11(struct struct_hfa_d11 e);
  func_hfa_d11((struct struct_hfa_d11){ 11, { 10, { 9, { 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } } } } });

  struct struct_hfa_d12 { double a; struct struct_hfa_d11 b; };
  struct struct_hfa_d12 func_hfa_d12(struct struct_hfa_d12 e);
  func_hfa_d12((struct struct_hfa_d12){ 12, { 11, { 10, { 9, { 8, { 7, { 6, { 5, { 4, { 3, { 1, { 2 } } } } } } } } } } } });

  return 0;
}
