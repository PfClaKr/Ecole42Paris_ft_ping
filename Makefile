CC = gcc
CFLAGS = -g3
SRCS = ping.c
OBJS = $(SRCS:.c=.o)
NAME = ft_shield

$(NAME): $(OBJS)
        $(CC) $(CFLAGS) -o $(NAME) $(OBJS)

%.o: %.c
        $(CC) $(CFLAGS) -c $< -o $@

clean:
        rm -f $(OBJS)

fclean: clean
        rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re