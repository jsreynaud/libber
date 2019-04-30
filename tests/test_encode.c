
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <debug/log.h>
#include <debug/hex.h>
#include <debug/memory.h>

#include <abz/error.h>
#include <abz/typedefs.h>

#include <ber/ber.h>

static int test_encode_1 (ber_t *e)
{
   static const uint32_t oid[] = { 10, 43, 6, 1, 2, 1, 2, 2, 1, 10, 1 };
   static const octet_string_t str = { len: 6, buf: (uint8_t *) "public" };
   static const uint8_t buf[] =
	 {
		0x30, 0x2b, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x1e,
		0x02, 0x04, 0x4a, 0x4e, 0x03, 0xc1, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x10, 0x30,
		0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0a, 0x01, 0x05, 0x00
	 };

   e->size = ARRAYSIZE (buf);

   if (ber_encode_null (e) < 0 ||
	   ber_encode_oid (e,oid) < 0 ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   ber_encode_integer (e,0) ||
	   ber_encode_integer (e,0) ||
	   ber_encode_integer (e,1246626753) ||
	   ber_encode_get_request (e) ||
	   ber_encode_octet_string (e,&str) ||
	   ber_encode_integer (e,0) ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   memcmp (buf,e->buf,e->size))
	 return (-1);

   return (0);
}

static int test_encode_2 (ber_t *e)
{
   static const uint32_t oid[] = { 10, 43, 6, 1, 2, 1, 2, 2, 1, 10, 1 };
   static const octet_string_t str = { len: 6, buf: (uint8_t *) "public" };
   static const uint8_t buf[] =
	 {
		0x30, 0x2f, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x22,
		0x02, 0x04, 0x4a, 0x4e, 0x03, 0xc1, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x14, 0x30,
		0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0a, 0x01, 0x41, 0x04,
		0x3f, 0x5e, 0xf5, 0xf6
	 };

   e->size = ARRAYSIZE (buf);

   if (ber_encode_counter32 (e,1063187958) < 0 ||
	   ber_encode_oid (e,oid) < 0 ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   ber_encode_integer (e,0) ||
	   ber_encode_integer (e,0) ||
	   ber_encode_integer (e,1246626753) ||
	   ber_encode_get_response (e) ||
	   ber_encode_octet_string (e,&str) ||
	   ber_encode_integer (e,0) ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   memcmp (buf,e->buf,e->size))
	 return (-1);

   return (0);
}

static int test_encode_3 (ber_t *e)
{
   int i;
   uint32_t offset;
   static const uint32_t oid[] =
	 {
		10, 43, 6, 1, 2, 1, 2, 2, 1, 10, 1,
		10, 43, 6, 1, 2, 1, 2, 2, 1, 16, 1,
		10, 43, 6, 1, 2, 1, 2, 2, 1, 13, 1,
		10, 43, 6, 1, 2, 1, 2, 2, 1, 19, 1,
		10, 43, 6, 1, 2, 1, 2, 2, 1, 14, 1,
		10, 43, 6, 1, 2, 1, 2, 2, 1, 20, 1,
		10, 43, 6, 1, 2, 1, 2, 2, 1, 7, 1,
		10, 43, 6, 1, 2, 1, 2, 2, 1, 8, 1
	 };
   static const uint8_t buf[] =
	 {
		0x30, 0x81, 0x9d, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x81,
		0x8f, 0x02, 0x04, 0x34, 0xc0, 0x3a, 0xa1, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x81, 0x80,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0a, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x10, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0d, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x13, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x0e, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x14, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x07, 0x01, 0x05, 0x00,
		0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x08, 0x01, 0x05, 0x00
	 };
   static const octet_string_t str = { len: 6, buf: (uint8_t *) "public" };

   e->size = ARRAYSIZE (buf);

   for (i = 7; i >= 0; i--)
	 {
		offset = e->offset;
		if (ber_encode_null (e) < 0 || ber_encode_oid (e,oid + i * 11) < 0 || ber_encode_sequence (e,e->offset - offset) < 0)
		  return (-1);
	 }

   if (ber_encode_sequence (e,e->offset) < 0 ||
	   ber_encode_integer (e,0) ||
	   ber_encode_integer (e,0) ||
	   ber_encode_integer (e,885013153) ||
	   ber_encode_get_request (e) ||
	   ber_encode_octet_string (e,&str) ||
	   ber_encode_integer (e,0) ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   memcmp (buf,e->buf,e->size))
	 return (-1);

   return (0);
}

static int test_encode_4 (ber_t *e)
{
   if (ber_encode_sequence (e,506) < 0 ||
	   e->offset != 4 ||
	   e->buf[e->size - e->offset] != 0x30 ||
	   e->buf[e->size - e->offset + 1] != 0x82 ||
	   e->buf[e->size - e->offset + 2] != 0x01 ||
	   e->buf[e->size - e->offset + 3] != 0xfa)
	 return (-1);

   return (0);
}

static int test_encode_5 (ber_t *e)
{
   static const uint32_t oid[] =
	 {
		26, 1, 1450, 2, 5, 768, 127, 128, 4294967295U, 1, 128, 256, 512,
		1024, 2048, 4096, 8192, 16384, 32768, 65536, 128000, 256000,
		512000, 1024000, 2048000, 4096000, 8192000
	 };

   static const uint8_t buf[] =
	 {
		0x06, 0x3e, 0x01, 0x8b, 0x2a, 0x02, 0x05, 0x86, 0x00, 0x7f, 0x81, 0x00, 0x8f, 0xff, 0xff, 0xff,
		0x7f, 0x01, 0x81, 0x00, 0x82, 0x00, 0x84, 0x00, 0x88, 0x00, 0x90, 0x00, 0xa0, 0x00, 0xc0, 0x00,
		0x81, 0x80, 0x00, 0x82, 0x80, 0x00, 0x84, 0x80, 0x00, 0x87, 0xe8, 0x00, 0x8f, 0xd0, 0x00, 0x9f,
		0xa0, 0x00, 0xbe, 0xc0, 0x00, 0xfd, 0x80, 0x00, 0x81, 0xfa, 0x80, 0x00, 0x83, 0xf4, 0x80, 0x00
	 };

   e->size = ARRAYSIZE (buf);

   if (ber_encode_oid (e,oid) < 0 || memcmp (buf,e->buf,e->size))
	 return (-1);

   return (0);
}

static int test_encode_6 (ber_t *e)
{
   static const uint32_t oid[14] = { 13, 43, 6, 1, 2, 1, 4, 21, 1, 1, 66, 8, 28, 17 };
   static const uint8_t buf[] =
	 {
		0x30, 0x32, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x25, 0x02,
		0x04, 0x2a, 0xa1, 0xac, 0x76, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x17, 0x30, 0x15, 0x06,
		0x0d, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x04, 0x15, 0x01, 0x01, 0x42, 0x08, 0x1c, 0x11, 0x40, 0x04,
		0x42, 0x08, 0x1c, 0x11
	 };
   static const octet_string_t str = { len: 6, buf: (uint8_t *) "public" };

   e->size = ARRAYSIZE (buf);

   if (ber_encode_ipaddress (e,0x111c0842) < 0 ||
	   ber_encode_oid (e,oid) < 0 ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   ber_encode_integer (e,0) ||
	   ber_encode_integer (e,0) ||
	   ber_encode_integer (e,0x2aa1ac76) ||
	   ber_encode_get_response (e) ||
	   ber_encode_octet_string (e,&str) ||
	   ber_encode_integer (e,0) ||
	   ber_encode_sequence (e,e->offset) < 0 ||
	   memcmp (buf,e->buf,e->size))
	 return (-1);

   return (0);
}

typedef int (*test_encode_t)(ber_t *);

static void test_encode (void)
{
   ber_t e;
   int i;
   static const test_encode_t test[] =
	 {
		test_encode_1,
		test_encode_2,
		test_encode_3,
		test_encode_4,
		test_encode_5,
		test_encode_6
	 };

   e.size = 65535;
   if ((e.buf = (uint8_t *) mem_alloc (e.size * sizeof (uint8_t))) == NULL)
	 {
		log_printf (LOG_ERROR,"failed to allocate memory: %m\n");
		exit (EXIT_FAILURE);
	 }

   for (i = 0; i < ARRAYSIZE (test); i++)
	 {
		e.size = 65535;
		e.offset = 0;

		if (test[i] (&e) < 0)
		  {
			 log_printf (LOG_ERROR,"encoding test %d failed\n",i + 1);
			 mem_free (e.buf);
			 exit (EXIT_FAILURE);
		  }

		log_printf (LOG_NORMAL,"encoding test %d succeeded\n",i + 1);
	 }

   mem_free (e.buf);
}

int main ()
{
   mem_open (NULL);
   log_open (NULL,LOG_NOISY,LOG_HAVE_COLORS);
   atexit (log_close);
   atexit (mem_close);

   test_encode ();

   exit (EXIT_SUCCESS);
}

