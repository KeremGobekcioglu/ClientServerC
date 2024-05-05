#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>

#define SERVER_FIFO "/tmp/server_fifo"
#define CLIENT_FIFO_NAME "/tmp/client_fifo_%ld"
#define CLIENT_FIFO_COMMANDS "/tmp/client_fifo_write_%ld"

void handle_sigint(int sig)
{
    // Perform any necessary cleanup tasks here

    // Exit the program
    exit(EXIT_SUCCESS);
}

void send_request(int server_fifo_fd, const char *request_type, pid_t server_pid)
{
    // Open the server FIFO for writing
    // Write the client's PID, server's PID and request type to the server FIFO
    char buffer[256] = {0};
    sprintf(buffer, "%ld,%ld,%s:", (long)getpid(), (long)server_pid, request_type);
    printf("Sending to server: %s\n", buffer);
    printf("Client pid = %ld\n", (long)getpid());
    write(server_fifo_fd, buffer, strlen(buffer));
    // close(server_fifo_fd);
    // unlink(SERVER_FIFO);
    memset(buffer, 0, sizeof(buffer));
}

/*void receive_response() {
    // Create a FIFO for this client
    char client_fifo_path[256];
    sprintf(client_fifo_path, CLIENT_FIFO_NAME, (long)getpid());
    mkfifo(client_fifo_path, 0666);

    // Open the client FIFO for reading
    int client_fifo_fd_read = open(client_fifo_path, O_RDONLY);
    if (client_fifo_fd_read == -1) {
        perror("open client fifo");
        exit(EXIT_FAILURE);
    }

    // Read the server's response from the client FIFO
    char buffer[256] = {0};
    memset(buffer, 0, sizeof(buffer));
    if (read(client_fifo_fd_read, buffer, sizeof(buffer)) > 0) {
        printf("Received from server: %s\n", buffer);
    }

    close(client_fifo_fd_read);
    unlink(client_fifo_path);
}*/
int issize(const char *str, int a)
{
    int i = 0;
    while (str[i] != '\0' && i < a)
    {
        if (str[i] != ' ' && (str[i] < '0' || str[i] > '9'))
        {
            return 0;
        }
        i++;
    }
    return 1;
}
int contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}
int possible_commands(char *str)
{
    // help , list , archServer, killServer , upload , download , writeT , readF
    if (contains(str, "help") || contains(str, "list") ||
        contains(str, "archServer") || contains(str, "killServer") ||
        contains(str, "upload") || contains(str, "download") ||
        contains(str, "writeT") || contains(str, "readF"))
    {
        return 1;
    }
}
void clean_fifo(int fd)
{
    char buffer[256];
    ssize_t bytes_read;
    do
    {
        bytes_read = read(fd, buffer, sizeof(buffer));
        if (bytes_read == -1)
        {
            perror("Error reading from FIFO");
            exit(EXIT_FAILURE);
        }
    } while (bytes_read > 0);
}
void receive_response(int server_fifo_fd)
{
    // Create a FIFO for this client
    char client_fifo_path[256] = {0};
    char client_fifo_path_commands[256] = {0};
    sprintf(client_fifo_path, CLIENT_FIFO_NAME, (long)getpid());
    mkfifo(client_fifo_path, 0666);
    sprintf(client_fifo_path_commands, CLIENT_FIFO_COMMANDS, (long)getpid());
    mkfifo(client_fifo_path_commands, 0666);
    // Open the client FIFO for reading
    int client_fifo_fd_read = open(client_fifo_path, O_RDONLY);
    if (client_fifo_fd_read == -1)
    {
        perror("open client fifo");
        exit(EXIT_FAILURE);
    }
    int client_fifo_fd_write = open(client_fifo_path_commands, O_WRONLY);
    if (client_fifo_fd_write == -1)
    {
        perror("open client fifo");
        exit(EXIT_FAILURE);
    }
    // Read the server's response from the client FIFO
    char buffer_for_write[256] = {0};
    char buffer_for_read[1024] = {0};
    memset(buffer_for_write, 0, sizeof(buffer_for_write));
    memset(buffer_for_read, 0, sizeof(buffer_for_read));
    printf("WHILEclient:\n");
    fflush(stdin);
    while (1)
    {
        printf("Enter a comment: ");
        if (fgets(buffer_for_write, sizeof(buffer_for_write), stdin) != NULL)
        {
            // Remove the trailing newline character
            if (buffer_for_write[0] == '\n' || buffer_for_write[0] == '\0')
                continue;
            buffer_for_write[strcspn(buffer_for_write, "\n")] = 0;
            printf("Sending to server: %sa\n", buffer_for_write);
            if (strcmp(buffer_for_write, "quit") == 0)
            {
                break;
            }
            // Write the command to the server
            if (possible_commands(buffer_for_write) == 1)
            {

                write(client_fifo_fd_write, buffer_for_write, strlen(buffer_for_write));
                if (read(client_fifo_fd_read, buffer_for_read, sizeof(buffer_for_read)) > 0)
                {
                    printf("%s\n", buffer_for_read);
                    if (strcmp(buffer_for_read, "Queue is full. Please try again later.\n") == 0)
                    {
                        return;
                    }
                    // memset(buffer_for_read, 0, sizeof(buffer_for_read));
                }
                if(strcmp(buffer_for_write,"killServer")==0)
                {
                    printf("SERVER SHUTDOWN\n");
                    break;
                }
            }
            else
            {
                printf("Invalid command\n");
            }

            // Read the response from the server
        }
        memset(buffer_for_write, 0, sizeof(buffer_for_write));
            memset(buffer_for_read, 0, sizeof(buffer_for_read));
    }
    printf("Client is exiting\n");
    close(client_fifo_fd_read);
    close(client_fifo_fd_write);
    unlink(client_fifo_path_commands);
    unlink(client_fifo_path);
}

int main(int argc, char *argv[])
{
    if (signal(SIGINT, handle_sigint) == SIG_ERR)
    {
        perror("signal");
        exit(EXIT_FAILURE);
    }
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <request_type> <server_pid>\n", argv[0]);
        return 1;
    }

    const char *request_type = argv[1];
    pid_t server_pid = (pid_t)strtol(argv[2], NULL, 10);

    int server_fifo_fd = open(SERVER_FIFO, O_WRONLY);
    if (server_fifo_fd == -1)
    {
        perror("open server fifo");
        exit(EXIT_FAILURE);
    }
    send_request(server_fifo_fd, request_type, server_pid);
    receive_response(server_fifo_fd);

    // close(server_fifo_fd);
    return 0;
}