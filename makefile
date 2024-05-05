all: compile

compile:
	@gcc -o server server.c -lpthread
	@gcc -o client client.c -lpthread
valgrind: compile
	@valgrind --leak-check=full ./server aaa 1
	@valgrind --leak-check=full ./client