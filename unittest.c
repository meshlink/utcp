#include <stdio.h>
#include <string.h>

#include "utcp_priv.h"
#include "minunit.h"

int tests_run = 0;

static char *test_buffer_init() {
	struct buffer buf;
	buffer_init(&buf, 0, 10);
	mu_assert("buffer wrong size", buf.size == 0);
	mu_assert("buffer not empty", buf.used == 0);
	mu_assert("buffer wrong max", buf.maxsize == 10);
	// len of 0 should not allocate a data array
	mu_assert("buffer not allocated", buf.data == NULL);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_free() {
	struct buffer buf;
	char data[4] = "data";
	buffer_init(&buf, 0, 10);
	// free space should be the max size, not the currently allocated memory
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 10);
	buffer_put(&buf, data, sizeof data);
	mu_assert("buffer free space incorrect after writing", buffer_free(&buf) == 6);
	mu_assert("buffer used wrong", buf.used == 4);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_put_at() {
	struct buffer buf;
	char data[4] = "data";
	buffer_init(&buf, 0, 10);
	ssize_t put = buffer_put_at(&buf, 0, data, sizeof data);
	mu_assert("buffer wrong amount put", put == 4);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 6);
	mu_assert("buffer used wrong", buf.used == 4);
	mu_assert("data put incorrect", buf.data[0] == data[0]);
	mu_assert("data put incorrect", buf.data[1] == data[1]);
	mu_assert("data put incorrect", buf.data[2] == data[2]);
	mu_assert("data put incorrect", buf.data[3] == data[3]);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_put_at_offset() {
	struct buffer buf;
	char data[4] = "data";
	buffer_init(&buf, 0, 10);
	ssize_t put = buffer_put_at(&buf, 8, data, sizeof data);
	mu_assert("buffer wrong amount put", put == 2);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 0);
	// putting with offset reports the preceding buffer area as used
	mu_assert("buffer used wrong", buf.used == buf.maxsize);
	mu_assert("data put incorrect", buf.data[8] == data[0]);
	mu_assert("data put incorrect", buf.data[9] == data[1]);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_put_at_too_large() {
	struct buffer buf;
	char data[4] = "data";
	buffer_init(&buf, 0, 3);
	ssize_t put = buffer_put_at(&buf, 0, data, sizeof data);
	mu_assert("buffer wrong amount put", put == 3);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 0);
	mu_assert("buffer used wrong", buf.used == buf.maxsize);
	mu_assert("data put incorrect", buf.data[0] == data[0]);
	mu_assert("data put incorrect", buf.data[1] == data[1]);
	mu_assert("data put incorrect", buf.data[2] == data[2]);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_get() {
	struct buffer buf;
	char data[4] = "data";
	buffer_init(&buf, 0, 10);
	buffer_put_at(&buf, 0, data, sizeof data);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 6);
	mu_assert("buffer used wrong", buf.used == 4);
	buffer_get(&buf, NULL, 3);
	mu_assert("buffer free space incorrect after get", buffer_free(&buf) == 9);
	mu_assert("buffer used wrong", buf.used == 1);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_get_copy() {
	struct buffer buf;
	char data[4] = "data";
	char actual[4];
	memset(actual, 0, sizeof actual);
	buffer_init(&buf, 0, 10);
	buffer_put_at(&buf, 0, data, sizeof data);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 6);
	mu_assert("buffer used wrong", buf.used == 4);
	buffer_get(&buf, actual, 3);
	mu_assert("buffer free space incorrect after get copy", buffer_free(&buf) == 9);
	mu_assert("buffer used wrong", buf.used == 1);
	mu_assert("data copied incorrect", data[0] == actual[0]);
	mu_assert("data copied incorrect", data[1] == actual[1]);
	mu_assert("data copied incorrect", data[2] == actual[2]);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_copy() {
	struct buffer buf;
	char data[4] = "data";
	char actual[4];
	memset(actual, 0, sizeof actual);
	buffer_init(&buf, 0, 10);
	buffer_put_at(&buf, 0, data, sizeof data);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 6);
	mu_assert("buffer used wrong", buf.used == 4);
	buffer_copy(&buf, actual, 0, 3);
	mu_assert("buffer free space incorrect after copy", buffer_free(&buf) == 6);
	mu_assert("buffer used wrong", buf.used == 4);
	mu_assert("data copied incorrect", buf.data[0] == actual[0]);
	mu_assert("data copied incorrect", buf.data[1] == actual[1]);
	mu_assert("data copied incorrect", buf.data[2] == actual[2]);
	mu_assert("data copied incorrect", data[0] == actual[0]);
	mu_assert("data copied incorrect", data[1] == actual[1]);
	mu_assert("data copied incorrect", data[2] == actual[2]);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_put_at_wrap() {
	struct buffer buf;
	char data[8] = "12345678";
	char actual[8];
	memset(actual, 0, sizeof actual);
	buffer_init(&buf, 10, 10);
	// to get the wrap we need to write at offset 5,
	// then consume the unused 5 bytes, then write at offset 5 again
	// (think of how this would work in a non-ring buffer)
	ssize_t put = buffer_put_at(&buf, 5, data, 5);
	mu_assert("buffer wrong amount put", put == 5);
	buffer_get(&buf, NULL, 5);
	put = buffer_put_at(&buf, 5, data + 5, 3);
	mu_assert("buffer wrong amount put", put == 3);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 2);
	buffer_copy(&buf, actual, 0, sizeof actual);
	mu_assert("data0 put incorrect", actual[0] == data[0]);
	mu_assert("data1 put incorrect", actual[1] == data[1]);
	mu_assert("data2 put incorrect", actual[2] == data[2]);
	mu_assert("data3 put incorrect", actual[3] == data[3]);
	mu_assert("data4 put incorrect", actual[4] == data[4]);
	mu_assert("data5 put incorrect", actual[5] == data[5]);
	mu_assert("data6 put incorrect", actual[6] == data[6]);
	mu_assert("data7 put incorrect", actual[7] == data[7]);

	// writing past buf.start should not be allowed
	char data2[4] = "data";
	char actual2[2];
	memset(actual2, 0, sizeof actual2);
	put = buffer_put_at(&buf, 8, data2, 4);
	mu_assert("buffer wrong amount put", put == 2);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 0);
	buffer_copy(&buf, actual2, 8, sizeof actual2);
	mu_assert("data20 put incorrect", actual2[0] == data2[0]);
	mu_assert("data21 put incorrect", actual2[1] == data2[1]);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_free_single_elem() {
	struct buffer buf;
	char data[1] = "d";
	buffer_init(&buf, 10, 10);
	buffer_put(&buf, data, sizeof data);
	mu_assert("buf.used wrong", buf.used == 1);
	mu_assert("buffer free space incorrect after writing", buffer_free(&buf) == 9);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_copy_wrap() {
	struct buffer buf;
	char data[8] = "12345678";
	char actual[8];
	memset(actual, 0, sizeof actual);
	buffer_init(&buf, 10, 10);
	// to get the wrap we need to write at offset 5,
	// then consume the unused 5 bytes, then write at offset 5 again
	// (think of how this would work in a non-ring buffer)
	ssize_t put = buffer_put_at(&buf, 5, data, 5);
	mu_assert("buffer wrong amount put", put == 5);
	buffer_get(&buf, NULL, 5);
	put = buffer_put_at(&buf, 5, data + 5, 3);
	mu_assert("buffer used wrong", buf.used == 8);
	buffer_copy(&buf, actual, 0, sizeof actual);
	mu_assert("buffer used wrong after copy", buf.used == 8);
	mu_assert("data copied incorrect", data[0] == actual[0]);
	mu_assert("data copied incorrect", data[1] == actual[1]);
	mu_assert("data copied incorrect", data[2] == actual[2]);
	mu_assert("data copied incorrect", data[3] == actual[3]);
	mu_assert("data copied incorrect", data[4] == actual[4]);
	mu_assert("data copied incorrect", data[5] == actual[5]);
	mu_assert("data copied incorrect", data[6] == actual[6]);
	mu_assert("data copied incorrect", data[7] == actual[7]);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_get_copy_wrap() {
	struct buffer buf;
	char data[8] = "12345678";
	char actual[8];
	memset(actual, 0, sizeof actual);
	buffer_init(&buf, 10, 10);
	// to get the wrap we need to write at offset 5,
	// then consume the unused 5 bytes, then write at offset 5 again
	// (think of how this would work in a non-ring buffer)
	ssize_t put = buffer_put_at(&buf, 5, data, 5);
	mu_assert("buffer wrong amount put", put == 5);
	buffer_get(&buf, NULL, 5);
	put = buffer_put_at(&buf, 5, data + 5, 3);
	mu_assert("buffer used wrong", buf.used == 8);
	buffer_get(&buf, actual, sizeof actual);
	// get() should consume the data
	mu_assert("buffer used wrong after copy", buf.used == 0);
	mu_assert("data copied incorrect", data[0] == actual[0]);
	mu_assert("data copied incorrect", data[1] == actual[1]);
	mu_assert("data copied incorrect", data[2] == actual[2]);
	mu_assert("data copied incorrect", data[3] == actual[3]);
	mu_assert("data copied incorrect", data[4] == actual[4]);
	mu_assert("data copied incorrect", data[5] == actual[5]);
	mu_assert("data copied incorrect", data[6] == actual[6]);
	mu_assert("data copied incorrect", data[7] == actual[7]);
	buffer_exit(&buf);
	return 0;
}

// put some data is it is wrapped around past the end of the buffer,
// then put additional data that triggers a buffer resize
static char *test_buffer_put_at_wrap_resize() {
	struct buffer buf;
	char data[15] = "123456789abcdef";
	char actual[15];
	memset(actual, 0, sizeof actual);
	buffer_init(&buf, 10, 15);
	// to get the wrap we need to write at offset 5,
	// then consume the unused 5 bytes, then write at offset 5 again
	// (think of how this would work in a non-ring buffer)
	ssize_t put = buffer_put_at(&buf, 5, data, 5);
	mu_assert("buffer wrong amount put", put == 5);
	mu_assert("buffer was resized", buf.size == 10);
	buffer_get(&buf, NULL, 5);
	put = buffer_put_at(&buf, 5, data + 5, 5);
	mu_assert("buffer wrong amount put", put == 5);
	mu_assert("buffer was resized", buf.size == 10);
	mu_assert("buffer free space incorrect", buffer_free(&buf) == 5);
	buffer_copy(&buf, actual, 0, 10);
	mu_assert("data0 put incorrect", actual[0] == data[0]);
	mu_assert("data1 put incorrect", actual[1] == data[1]);
	mu_assert("data2 put incorrect", actual[2] == data[2]);
	mu_assert("data3 put incorrect", actual[3] == data[3]);
	mu_assert("data4 put incorrect", actual[4] == data[4]);
	mu_assert("data5 put incorrect", actual[5] == data[5]);
	mu_assert("data6 put incorrect", actual[6] == data[6]);
	mu_assert("data7 put incorrect", actual[7] == data[7]);
	mu_assert("data8 put incorrect", actual[8] == data[8]);
	mu_assert("data9 put incorrect", actual[9] == data[9]);
	put = buffer_put_at(&buf, 10, data + 10, 5);
	mu_assert("buffer was not resized", buf.size == 15);
	memset(actual, 0, sizeof actual);
	buffer_copy(&buf, actual, 0, 15);
	mu_assert("data0 put incorrect", actual[0] == data[0]);
	mu_assert("data1 put incorrect", actual[1] == data[1]);
	mu_assert("data2 put incorrect", actual[2] == data[2]);
	mu_assert("data3 put incorrect", actual[3] == data[3]);
	mu_assert("data4 put incorrect", actual[4] == data[4]);
	mu_assert("data5 put incorrect", actual[5] == data[5]);
	mu_assert("data6 put incorrect", actual[6] == data[6]);
	mu_assert("data7 put incorrect", actual[7] == data[7]);
	mu_assert("data8 put incorrect", actual[8] == data[8]);
	mu_assert("data9 put incorrect", actual[9] == data[9]);
	mu_assert("data10 put incorrect", actual[10] == data[10]);
	mu_assert("data11 put incorrect", actual[11] == data[11]);
	mu_assert("data12 put incorrect", actual[12] == data[12]);
	mu_assert("data13 put incorrect", actual[13] == data[13]);
	mu_assert("data14 put incorrect", actual[14] == data[14]);

	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_put_at_resize() {
	struct buffer buf;
	char data[15] = "123456789abcdef";
	buffer_init(&buf, 10, 15);
	// to get the wrap we need to write at offset 5,
	// then consume the unused 5 bytes, then write at offset 5 again
	// (think of how this would work in a non-ring buffer)
	ssize_t put = buffer_put_at(&buf, 0, data, 10);
	mu_assert("buffer wrong amount put", put == 10);
	mu_assert("buffer was resized", buf.size == 10);
	put = buffer_put_at(&buf, 10, data + 10, 5);
	mu_assert("buffer wrong amount put", put == 5);
	mu_assert("buffer was not resized", buf.size == 15);
	mu_assert("data0 put incorrect", buf.data[0] == data[0]);
	mu_assert("data1 put incorrect", buf.data[1] == data[1]);
	mu_assert("data2 put incorrect", buf.data[2] == data[2]);
	mu_assert("data3 put incorrect", buf.data[3] == data[3]);
	mu_assert("data4 put incorrect", buf.data[4] == data[4]);
	mu_assert("data5 put incorrect", buf.data[5] == data[5]);
	mu_assert("data6 put incorrect", buf.data[6] == data[6]);
	mu_assert("data7 put incorrect", buf.data[7] == data[7]);
	mu_assert("data8 put incorrect", buf.data[8] == data[8]);
	mu_assert("data9 put incorrect", buf.data[9] == data[9]);
	mu_assert("data10 put incorrect", buf.data[10] == data[10]);
	mu_assert("data11 put incorrect", buf.data[11] == data[11]);
	mu_assert("data12 put incorrect", buf.data[12] == data[12]);
	mu_assert("data13 put incorrect", buf.data[13] == data[13]);
	mu_assert("data14 put incorrect", buf.data[14] == data[14]);

	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_copy_offset() {
	struct buffer buf;
	char data[8] = "12345678";
	char actual[4];
	memset(actual, 0, sizeof actual);
	buffer_init(&buf, 10, 10);
	// to get the wrap we need to write at offset 5,
	// then consume the unused 5 bytes, then write at offset 5 again
	// (think of how this would work in a non-ring buffer)
	ssize_t put = buffer_put_at(&buf, 0, data, sizeof data);
	mu_assert("buffer wrong amount put", put == 8);
	mu_assert("buffer used wrong", buf.used == 8);
	buffer_copy(&buf, actual, 1, sizeof actual);
	mu_assert("buffer used wrong after copy", buf.used == 8);
	mu_assert("data copied incorrect", data[1] == actual[0]);
	mu_assert("data copied incorrect", data[2] == actual[1]);
	mu_assert("data copied incorrect", data[3] == actual[2]);
	buffer_exit(&buf);
	return 0;
}

static char *test_buffer_get_wrap() {
	struct buffer buf;
	char data[8] = "12345678";
	buffer_init(&buf, 10, 10);
	// to get the wrap we need to write at offset 5,
	// then consume the unused 5 bytes, then write at offset 5 again
	// (think of how this would work in a non-ring buffer)
	ssize_t put = buffer_put_at(&buf, 5, data, 5);
	mu_assert("buffer wrong amount put", put == 5);
	mu_assert("buffer.used wrong", buf.used == 10);
	buffer_get(&buf, NULL, 5);
	put = buffer_put_at(&buf, 5, data + 5, 3);
	mu_assert("buffer used wrong", buf.used == 8);
	buffer_get(&buf, NULL, 8);
	// get() should consume the data
	mu_assert("buffer used wrong after get", buf.used == 0);
	buffer_exit(&buf);
	return 0;
}

// data is wrapped in buffer and offset is larger than the data at the end
static char *test_buffer_copy_wrap_huge_offset() {
	struct buffer buf;
	char data[15] = "123456789abcdef";
	char actual[15];
	memset(actual, 0, sizeof actual);
	buffer_init(&buf, 20, 20);
	// to get the wrap we need to write at offset 5,
	// then consume the unused 5 bytes, then write at offset 5 again
	// (think of how this would work in a non-ring buffer)
	ssize_t put = buffer_put_at(&buf, 15, data, 5);
	mu_assert("buffer wrong amount put", put == 5);
	mu_assert("buffer.used wrong", buf.used == 20);
	buffer_get(&buf, NULL, 15);
	put = buffer_put_at(&buf, 5, data + 5, 10);
	mu_assert("buffer used wrong", buf.used == 15);
	buffer_copy(&buf, actual, 10, sizeof actual);
	mu_assert("buffer used wrong after copy", buf.used == 15);
	mu_assert("data copied incorrect", data[10] == actual[0]);
	mu_assert("data copied incorrect", data[11] == actual[1]);
	mu_assert("data copied incorrect", data[12] == actual[2]);
	mu_assert("data copied incorrect", data[13] == actual[3]);
	mu_assert("data copied incorrect", data[14] == actual[4]);
	mu_assert("data copied incorrect", data[15] == actual[5]);
	buffer_exit(&buf);
	return 0;
}

static char *all_tests() {
	mu_run_test(test_buffer_init);
	mu_run_test(test_buffer_free);
	mu_run_test(test_buffer_put_at);
	mu_run_test(test_buffer_put_at_offset);
	mu_run_test(test_buffer_put_at_too_large);
	mu_run_test(test_buffer_get);
	mu_run_test(test_buffer_get_copy);
	mu_run_test(test_buffer_copy);
	mu_run_test(test_buffer_free_single_elem);
	mu_run_test(test_buffer_put_at_wrap);
	mu_run_test(test_buffer_copy_wrap);
	mu_run_test(test_buffer_get_copy_wrap);
	mu_run_test(test_buffer_put_at_wrap_resize);
	mu_run_test(test_buffer_put_at_resize);
	mu_run_test(test_buffer_copy_offset);
	mu_run_test(test_buffer_get_wrap);
	mu_run_test(test_buffer_copy_wrap_huge_offset);
	return 0;
}

int main(int argc, char **argv) {
	char *result = all_tests();
	if (result != 0) {
		printf("%s\n", result);
	} else {
		printf("ALL TESTS PASSED\n");
	}
	printf("Tests run: %d\n", tests_run);

	return result != 0;
}

