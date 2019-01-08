#ifndef __EOS_TOKENPARSE_H__
#define __EOS_TOKENPARSE_H__

/**
 * Description-
 *
 *      given input and input_len and token character,
 *      the function parses the input tokenwise into the output buf or length op_len (for buffer overruns)
 *
 *      each time, this function returns the offset of the input that is being parsed.
 *
 *      The function may be called repeatedly passing the previous offset into the off till the function returns -1
 */
int edge_os_token_parser(const char *input, int input_len, char token, char *op, int op_len, int off);

#endif

