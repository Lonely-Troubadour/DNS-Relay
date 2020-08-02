#include <stdio.h>
#include "dnsutils.h"


int main(int argc, char const *argv[])
{
  // request baidu.com domain
  unsigned char request_domain[] = {0X55, 0Xc2, 0X81, 0X80, 0X00, 0X01, 0X00, 0X02, 0X00, 0X00, 0X00, 0X00, 0X05, 0X62, 0X61, 0X69,
                                    0X64, 0X75, 0X03, 0X63, 0X6f, 0X6d, 0X00, 0X00, 0X01, 0X00, 0X01, 0Xc0, 0X0c, 0X00, 0X01, 0X00,
                                    0X01, 0X00, 0X00, 0X01, 0Xe3, 0X00, 0X04, 0X27, 0X9c, 0X45, 0X4f, 0Xc0, 0X0c, 0X00, 0X01, 0X00,
                                    0X01, 0X00, 0X00, 0X01, 0Xe3, 0X00, 0X04, 0Xdc, 0Xb5, 0X26, 0X94};

  struct query queries[MAX_QUERIES];
  int parse_res = 0;

  parse_res = parse_query(request_domain, sizeof(request_domain), queries, SIZEOF_ARR(queries));
  if (parse_res == 0)
  {
    // printf("%s", name);
    printf("success to parse query info {name: %s, type: %d, class: %d}\n", queries[0].name, queries[0].ques.qtype, queries[0].ques.qclass);
  }
  else
  {
    printf("failed to parse query info, return %d\n", parse_res);
  }
  return 0;
}
