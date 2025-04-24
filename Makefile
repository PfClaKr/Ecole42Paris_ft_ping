CC = gcc
CFLAGS = -g3
SRCS = ping.c
OBJS = $(SRCS:.c=.o)
NAME = ft_ping

$(NAME): $(OBJS)
		$(CC) $(CFLAGS) -o $(NAME) $(OBJS) -lm

all: $(NAME)

%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@ -lm

clean:
		rm -f $(OBJS)

fclean: clean
		rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re