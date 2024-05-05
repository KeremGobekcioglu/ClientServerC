#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>

#define SERVER_FIFO "/tmp/server_fifo"
#define CLIENT_FIFO_NAME "/tmp/client_fifo_%ld"

void send_request(const char *request_type, pid_t server_pid)
{
    // Open the server FIFO for writing
    int server_fifo_fd = open(SERVER_FIFO, O_WRONLY);
    if (server_fifo_fd == -1)
    {
        perror("open server fifo");
        exit(EXIT_FAILURE);
    }

    // Write the client's PID, server's PID and request type to the server FIFO
    char buffer[256];
    sprintf(buffer, "%ld,%ld,%s:", (long)getpid(), (long)server_pid, request_type);
    printf("Sending to server: %s\n", buffer);
    printf("Client pid = %ld\n", (long)getpid());
    write(server_fifo_fd, buffer, strlen(buffer));
    memset(buffer, 0, sizeof(buffer));
    close(server_fifo_fd);
}

void receive_response()
{
    // Create a FIFO for this client
    char client_fifo_path[256];
    sprintf(client_fifo_path, CLIENT_FIFO_NAME, (long)getpid());
    mkfifo(client_fifo_path, 0666);

    // Open the client FIFO for reading
    int client_fifo_fd = open(client_fifo_path, O_RDONLY);
    if (client_fifo_fd == -1)
    {
        perror("open client fifo");
        exit(EXIT_FAILURE);
    }
    int server_fifo_fd = open(SERVER_FIFO, O_WRONLY);
    if (server_fifo_fd == -1)
    {
        perror("open server fifo");
        exit(EXIT_FAILURE);
    }
    // Read the server's response from the client FIFO
    char buffer[256];
    char input[256];
    printf("WHILEclient:\n");
    while (1)
    {
        printf("Enter a comment: ");
        memset(buffer, 0, sizeof(buffer));
        if (fgets(buffer, sizeof(buffer), stdin) != NULL)
        {
            // Remove the trailing newline character
            buffer[strcspn(buffer, "\n")] = 0;
            printf("Sending to server: %s\n", buffer);
            if(strcmp(buffer, "exit") == 0) {
                break;
            }
            // Write the command to the server
            write(server_fifo_fd, buffer, strlen(buffer));

            // Read the response from the server
            memset(buffer, 0, sizeof(buffer));
            if (read(client_fifo_fd, buffer, sizeof(buffer)) > 0)
            {
                printf("%s\n", buffer);
            }
        }
    }

    close(client_fifo_fd);
    unlink(client_fifo_path);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <request_type> <server_pid>\n", argv[0]);
        return 1;
    }

    const char *request_type = argv[1];
    pid_t server_pid = (pid_t)strtol(argv[2], NULL, 10);

    send_request(request_type, server_pid);
    receive_response();

    return 0;
}