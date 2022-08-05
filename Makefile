##
## Makefile for le-fuzzer-con
##

NAME	= le-fuzzer-con
SRCS	= le-fuzzer-con.c
OBJS	= $(SRCS:.c=.o)

CC	= gcc
CFLAGS	= -Wall -Wextra -Werror
GFLAGS = -g
RM	= rm -f


all	: $(NAME)

$(NAME) : $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS)
	@ echo "Done compiling $(NAME)."

debug : $(OBJS)
	$(CC) $(CFLAGS) $(GFLAGS) -o $(NAME) $(OBJS)
	@ echo "Done compiling $(NAME) (debug)."

clean	:
	$(RM) $(OBJS)
	@ echo "Cleaned."

fclean	:
	$(RM) $(OBJS) $(NAME)
	@ echo "Cleaned."

re	: fclean all
