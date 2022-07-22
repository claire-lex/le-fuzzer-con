##
## Makefile for le-fuzzer-con
##

NAME	= le-fuzzer-con
SRCS	= le-fuzzer-con.c
OBJS	= $(SRCS:.c=.o)

CC	= gcc
CFLAGS	= -W
GFLAGS = -ggdb
RM	= rm -f


all	: $(NAME)

$(NAME) : $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS)
	@ echo "\033[1;5;35m--> $(NAME) : C o m p i l a t i o n   C o m p l e t e\033[0m"

debug : $(OBJS)
	$(CC) $(CFLAGS) $(GFLAGS) -o $(NAME) $(OBJS)
	@ echo "\033[1;5;35m--> $(NAME) : [DEBUG] C o m p i l a t i o n   C o m p l e t e\033[0m"

clean	:
	$(RM) $(OBJS)
	@ echo "\033[0;35m--> $(NAME) : C l e a n e d\033[0m"

fclean	:
	$(RM) $(OBJS) $(NAME)
	@ echo "\033[0;35m--> $(NAME) : C l e a n e d\033[0m"

re	: fclean all
