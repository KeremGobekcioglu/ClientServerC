#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include "queue.h"
#include "queue_func.c"
#define SERVER_FIFO "/tmp/server_fifo"
#define LOG_FILE "server_log.txt"
#define CLIENT_FIFO_NAME "/tmp/client_fifo_%ld"
#define CLIENT_FIFO_COMMANDS "/tmp/client_fifo_write_%ld"
#define DEQUEUE "tmp/dequeue"
int log_fd; // Global log file descriptor
int num_clients = 0;

void write_log(const char *message)
{
    if (log_fd != -1)
    {
        write(log_fd, message, strlen(message));
        write(log_fd, "\n", 1);
    }
}
void handle_sigint(int sig)
{
    write_log("Received SIGINT. Server is shutting down...");
    close(log_fd);
    unlink(SERVER_FIFO);
    exit(0);
}
// catch exit
void sigusr1_handler(int signum)
{
    if (signum == SIGUSR1)
    {
        // Handle client termination
        printf("Received SIGUSR1\n");
        num_clients--; // Decrement the count of active clients
    }
}

void handle_sigchld(int sig)
{
    // Clean up any terminated child processes
    printf("Num clients before = %d\n", num_clients);
    int a = 0;
    while ((a = waitpid(-1, NULL, WNOHANG)) > 0)
    {
        printf("Child process %d terminated\n", a);
        // num_clients--;
    }
    printf("Num clients after = %d\n", num_clients);
}

void setup_fifo()
{
    if (mkfifo(SERVER_FIFO, 0666) == -1)
    {
        if (errno != EEXIST)
        {
            write_log("Failed to create FIFO");
            exit(1);
        }
    }
}
/*okay now i should handle commands*/
// STRTOK
void list(int client_fd_write)
{
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    char message[1024] = {0};
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            // Append the directory name to the message, instead of overwriting it
            strncat(message, dir->d_name, sizeof(message) - strlen(message) - 1);
            strncat(message, "\n", sizeof(message) - strlen(message) - 1);
        }
        closedir(d);
    }
    write(client_fd_write, message, strlen(message));
}
// STRTOK
int write_to_file(const char *filename, const char *content, int client_fd_write)
{
    // Open the file with write mode, creating if it doesn't exist, and append at the end
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1)
    {
        perror("open");
        write(client_fd_write, "Error opening file.\n", 20);
        return 0;
    }

    // Write content to the file
    if (write(fd, content, strlen(content)) == -1)
    {
        perror("write");
        write(client_fd_write, "Error writing content to file.\n", 30);
        return 0;
    }

    // Append newline if necessary
    if (content[strlen(content) - 1] != '\n')
    {
        if (write(fd, "\n", 1) == -1)
        {
            perror("write");
            write(client_fd_write, "Error writing newline character.\n", 31);
            return 0;
        }
    }

    close(fd);
    return 1;
}
int readF(int client_fd_write, char *buffer)
{
    char *filename = strtok(NULL, " ");
    if (filename == NULL)
    {
        char message[] = "Missing file name.\n";
        write(client_fd_write, message, sizeof(message));
        return 0;
    }

    char *line_number_str = strtok(NULL, "\0");
    int line_number = line_number_str != NULL ? atoi(line_number_str) : -1;
    int file = open(filename, O_RDONLY);
    if (file < 0)
    {
        char message[] = "Could not open file.\n";
        write(client_fd_write, message, sizeof(message));
        return 0;
    }
    char line[256] = {0};
    int current_line_number = 1;
    char *file_contents = NULL;
    size_t file_size = 0;
    int i = 0;
    char ch;
    while (read(file, &ch, 1) > 0)
    {
        if (ch == '\n')
        {
            current_line_number++;
        }
        else if (current_line_number == line_number)
        {
            line[i] = ch;
            ++i;
        }
    }
    lseek(file, 0, SEEK_SET);
    if (line_number <= 0 || current_line_number < line_number)
    {
        // Count the number of bytes in the file
        char ch;
        while (read(file, &ch, 1) > 0)
        {
            file_size++;
        }

        // Allocate an array of the appropriate size
        file_contents = malloc(file_size + 1); // +1 for the null terminator

        // Go back to the beginning of the file
        lseek(file, 0, SEEK_SET);

        // Read the entire file into the array
        read(file, file_contents, file_size);

        // Null-terminate the string
        file_contents[file_size] = '\0';
    }
    else
    {
        // Read the specified line
        line[i] = '\0'; // Null-terminate the string
        write(client_fd_write, line, strlen(line));
    }

    close(file);

    if (file_contents != NULL)
    {
        printf("%s\n", file_contents);
        write(client_fd_write, file_contents, file_size);
        free(file_contents);
    }
    return 1;
}

int upload_file(int client_fd_write, char *filename, int client_pid)
{
    // Open the source file in the client's directory
    write(client_fd_write, "File transfer request received. Beginning file transfer:", 59);
    char src_path[256];
    sprintf(src_path, "Client_%d/%s", client_pid, filename);
    int src_fd = open(src_path, O_RDONLY);
    if (src_fd == -1)
    {
        perror("Could not open source file");
        write(client_fd_write, "Could not open source file.", 27);
        return 0;
    }

    // Open the destination file in the server's directory
    int dest_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd == -1)
    {
        perror("Could not open destination file");
        close(src_fd);
        write(client_fd_write, "Could not open destination file.", 32);
        return 0;
    }

    // Read the source file byte by byte and write it to the destination file
    char byte;
    ssize_t bytes_read;
    int counter = 0;
    while ((bytes_read = read(src_fd, &byte, 1)) > 0)
    {
        if (write(dest_fd, &byte, 1) != 1)
        {
            perror("Write error");
            write(client_fd_write, "Write error.", 12);
            close(src_fd);
            close(dest_fd);
            return 0;
        }
        ++counter;
    }

    // Check if read error occurred
    if (bytes_read == -1)
    {
        perror("Read error");
        write(client_fd_write, "Read error.", 11);
        close(src_fd);
        close(dest_fd);
        return 0;
    }

    // Close the file descriptors
    close(src_fd);
    close(dest_fd);
    // coutner %d bytes transferred
    char message[256];
    sprintf(message, "%d bytes transferred", counter);
    write(client_fd_write, message, strlen(message));
    // write(client_fd_write, "File uploaded successfully.", 27);
    return 1;
}
int download_file(int client_fd_write, char *filename, int client_pid, char *messagefromarch)
{
    // Open the source file in the server's directory
    sprintf(messagefromarch, "Downloading file %s...\n", filename);
    int src_fd = open(filename, O_RDONLY);
    if (src_fd == -1)
    {
        perror("Could not open source file");
        write(client_fd_write, "Could not open source file.", 27);
        return 0;
    }

    // Create a directory with the PID of the current process
    char dir_name[256];
    sprintf(dir_name, "Client_%d", client_pid);

    // Open the destination file in the client's directory
    char dest_path[256];
    sprintf(dest_path, "%s/%s", dir_name, filename);
    int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd == -1)
    {
        perror("Could not open destination file");
        close(src_fd);
        write(client_fd_write, "Could not open destination file.", 32);
        return 0;
    }

    // Read the source file byte by byte and write it to the destination file
    char byte;
    ssize_t bytes_read;
    int counter = 0;
    while ((bytes_read = read(src_fd, &byte, 1)) > 0)
    {
        if (write(dest_fd, &byte, 1) != 1)
        {
            perror("Write error");
            write(client_fd_write, "Write error.", 12);
            close(src_fd);
            close(dest_fd);
            return 0;
        }
        ++counter;
    }
    sprintf(messagefromarch, "%d bytes transferred", counter);
    // Check if read error occurred
    if (bytes_read == -1)
    {
        perror("Read error");
        write(client_fd_write, "Read error.", 11);
        close(src_fd);
        close(dest_fd);
        return 0;
    }

    // Close the file descriptors
    close(src_fd);
    close(dest_fd);
    write(client_fd_write, messagefromarch, strlen(messagefromarch));
    return 1;
}

void command_help(int client_fd_write, char *command)
{
    char message[256];
    printf("COMMAND = %sada\n", command);
    if (strcmp(command, "help") == 0)
    {
        sprintf(message, "Available commands are:\nhelp, list, readF, writeT, upload, download, archServer, quit, killServer\n");
        write(client_fd_write, message, strlen(message));
    }
    else
    {
        char *token = strchr(command, ' ');
        token = token + 1;
        printf("TOKENINLASTFUNC = %sada\n", token);
        if (token != NULL)
        {
            if (strcmp(token, "readF") == 0)
            {
                sprintf(message, "readF <file> <line #>\nDisplay the #th line of the <file>, returns with an error if <file> does not exist.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "list") == 0)
            {
                sprintf(message, "list\nLists all the files in the current directory.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "writeT") == 0)
            {
                sprintf(message, "writeT <file> <line #> <text>\nWrites <text> to the #th line of the <file>, creates the file if it does not exist.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "upload") == 0)
            {
                sprintf(message, "upload <file>\nUploads the specified <file> to the server.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "download") == 0)
            {
                sprintf(message, "download <file>\nDownloads the specified <file> from the server.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "archServer") == 0)
            {
                sprintf(message, "archServer\nArchives the server.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "quit") == 0)
            {
                sprintf(message, "quit\nQuits the application.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "killServer") == 0)
            {
                sprintf(message, "killServer\nKills the server process.\n");
                write(client_fd_write, message, strlen(message));
            }
            else
            {
                sprintf(message, "Invalid command.\n");
                write(client_fd_write, message, strlen(message));
            }
        }
    }
}
int archive_server_files(int client_fd_write, char *filename, char *server_dir_name, int client_pid)
{
    char server_dir[50];
    strncpy(server_dir, server_dir_name, sizeof(server_dir) - 1);
    server_dir[sizeof(server_dir) - 1] = '\0';

    char message[1024] = {0};
    strncat(message, "Archiving server files in ", sizeof(message) - strlen(message) - 1);
    strncat(message, server_dir, sizeof(message) - strlen(message) - 1);
    strncat(message, "...\n", sizeof(message) - strlen(message) - 1);
    strncat(message, "creating archive directory ", sizeof(message) - strlen(message) - 1);
    strncat(message, server_dir_name, sizeof(message) - strlen(message) - 1);
    strncat(message, "\n", sizeof(message) - strlen(message) - 1);

    // Create a child process
    pid_t pid = fork();

    if (pid < 0)
    {
        // Fork failed
        printf("Fork failed.\n");
        return 0;
    }
    else if (pid == 0)
    {
        // Child process
        strncat(message, "Calling tar utility... child PID ", sizeof(message) - strlen(message) - 1);
        char pid_str[20];
        snprintf(pid_str, sizeof(pid_str), "%d", getpid());
        strncat(message, pid_str, sizeof(message) - strlen(message) - 1);
        strncat(message, "\n", sizeof(message) - strlen(message) - 1);
        execl("/bin/tar", "tar", "-C", server_dir, "-cvf", filename, server_dir_name, NULL);

        // If execlp returns, it means there was an error
        printf("execlp failed.\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        // Parent process
        // Wait for the child process to finish
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        {
            printf("Child returned with SUCCESS.\n");
        }
        else
        {
            printf("Child process failed.\n");
        }
    }

    // Get the size of the tar file
    struct stat st;
    if (stat(filename, &st) == 0)
    {
        strncat(message, "The size of ", sizeof(message) - strlen(message) - 1);
        strncat(message, filename, sizeof(message) - strlen(message) - 1);
        strncat(message, " is ", sizeof(message) - strlen(message) - 1);
        char size_str[50];
        snprintf(size_str, sizeof(size_str), "%lld bytes.\n", (long long)st.st_size);
        strncat(message, size_str, sizeof(message) - strlen(message) - 1);
    }
    else
    {
        perror("stat");
    }

    // Count the number of files in the tar archive
    char command[256];
    snprintf(command, sizeof(command), "tar -tf %s | wc -l", filename);
    FILE *fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("popen");
    }
    else
    {
        int file_count;
        if (fscanf(fp, "%d", &file_count) == 1)
        {
            strncat(message, "The archive ", sizeof(message) - strlen(message) - 1);
            strncat(message, filename, sizeof(message) - strlen(message) - 1);
            strncat(message, " contains ", sizeof(message) - strlen(message) - 1);
            char count_str[20];
            snprintf(count_str, sizeof(count_str), "%d files.\n", file_count);
            strncat(message, count_str, sizeof(message) - strlen(message) - 1);
        }
        pclose(fp);
    }

    // Copy the archive file code here...
    strncat(message, "Copying the archive file...\n", sizeof(message) - strlen(message) - 1);
    strncat(message, "Removing archive directory ", sizeof(message) - strlen(message) - 1);
    strncat(message, filename, sizeof(message) - strlen(message) - 1);

    download_file(client_fd_write, filename, client_pid, message);

    // remove archive form here
    if (remove(filename) == 0)
    {
        strncat(message, "Archive file ", sizeof(message) - strlen(message) - 1);
        strncat(message, filename, sizeof(message) - strlen(message) - 1);
        strncat(message, " removed successfully.\n", sizeof(message) - strlen(message) - 1);
    }
    else
    {
        perror("remove");
    }

    strncat(message, "SUCCESS Server side files are archived in ", sizeof(message) - strlen(message) - 1);
    strncat(message, filename, sizeof(message) - strlen(message) - 1);
    strncat(message, "\n", sizeof(message) - strlen(message) - 1);
    return 1;
}
int contains_string(char *haystack, char *needle) {
    return strstr(haystack, needle) != NULL;
}
int comments(char *buffer, int client_fd_write, int server, char *server_dir_name, int client_pid)
{
    // Get the command name
    char temp[strlen(buffer) + 1];
    strcpy(temp, buffer);
    char *token = strtok(temp, " ");
    char message[256];
    int return_value = 0;
    if (token != NULL)
    {
        if (contains_string(token, "help") == 1)
        {
            // Pass the rest of the command to the command_help function
            command_help(client_fd_write, buffer);
            return 1;
        }
        else if (contains_string(token, "list") == 1)
        {
            // Call your function to handle the "list" command here
            sprintf(message, "List command executed. Client PID = %d\n", client_pid);
            write_log(message);
            list(client_fd_write);
            return 1;
        }
        else if (contains_string(token, "readF") == 1)
        {
            // Call your function to handle the "readF" command here
            return_value = readF(client_fd_write, buffer);
            if (return_value == 0)
            {
                write(client_fd_write, "Error reading file.\n", 21);
            }
            return return_value;
        }
        else if (contains_string(token, "writeT") == 1)
        {
            char *filename = strtok(NULL, " ");
            // printf("FILENAME = %s\n", filename);
            if (filename == NULL)
            {
                char message[] = "Missing file name.\n";
                write(client_fd_write, message, sizeof(message));
                return 0;
            }

            char *line_number_str = strtok(NULL, " ");
            int line_number = line_number_str != NULL ? atoi(line_number_str) : -1;
            char *content;
            if (line_number != 0)
                content = strtok(NULL, "\n");
            else
                content = line_number_str;
            if (content == NULL)
            {
                char message[] = "Missing content to write.\n";
                write(client_fd_write, message, sizeof(message));
                return 0;
            }
            int return_value = write_to_file(filename, content, client_fd_write);
            if (return_value == 1)
            {
                write(client_fd_write, "Content written to file.\n", 26);
                sprintf(message, "writeT command executed. Client PID = %d\n", client_pid);
                write_log(message);
            }
            else
            {
                sprintf(message, "Error writing to file. Client PID = %d\n", client_pid);
                write_log(message);
            }
            return return_value;
        }
        else if (contains_string(token, "upload") == 1)
        {
            char *filename = strtok(NULL, " ");
            // printf("FILENAME = %s\n", filename);
            if (filename == NULL)
            {
                char message[] = "Missing file name.\n";
                write(client_fd_write, message, sizeof(message));
                return 0;
            }
            return_value = upload_file(client_fd_write, filename, client_pid);
            if (return_value == 1)
            {
                write_log("File uploaded successfully.");
            }
            else
            {
                write_log("Error uploading file.");
            }
        }
        else if (contains_string(token, "download") == 1)
        {
            // Call your function to handle the "download" command here
            char *filename = strtok(NULL, " ");
            if (filename == NULL)
            {
                char message[] = "Missing file name.\n";
                write(client_fd_write, message, sizeof(message));
                return 0;
            }
            char messagefromarch[1024] = {0};
            return_value = download_file(client_fd_write, filename, client_pid, messagefromarch);
            if (return_value == 1)
            {
                write_log("File downloaded successfully.");
            }
            else
            {
                write_log("Error downloading file.");
            }
        }

        else if (contains_string(token, "archServer") == 1)
        {
            char *filename = strtok(NULL, " ");
            char cwd[1024];

            // Get the current working directory
            if (getcwd(cwd, sizeof(cwd)) != NULL)
            {
                // Call your function to handle the "archServer" command
                return_value = archive_server_files(client_fd_write, filename, cwd, client_pid);
                if (return_value == 1)
                {
                    write_log("Server archived successfully.");
                }
                else
                {
                    write_log("Error archiving server.");
                }
                return return_value;
            }
            else
            {
                perror("getcwd() error");
                write(client_fd_write, "Error getting current working directory.\n", 40);
                write_log("Error getting current working directory. Could not archive server.");
                return -1;
            }
        }
        else if (contains_string(token, "quit") == 1)
        {
            // Call your function to handle the "quit" command here
            return 0;
        }
        else if (contains_string(token, "killServer") == 1)
        {
            // Call your function to handle the "killServer" command here
            printf("Kill signal from client %d.. terminating...\n", client_pid);
            write(client_fd_write, "Server is shutting down...", 26);
            // kill signal from client05.. terminating...
            // printf("Kill signal from client %d.. terminating...\n", client_pid);
            kill(server, SIGINT);
            return 0;
        }
        return 0;
    }
    else
    {
        char message[] = "Invalid command.\n";
        write(client_fd_write, message, sizeof(message));
        return 0;
    }
}
/*okay now i should handle commands*/

void serve_client(int client_fd_write, int client_fd_read, int server, char *server_dir_name, int client_pid)
{
    // Send a message to the client

    // Buffer to hold the client's commands
    printf("Client connected\n");
    char buffer[256] = {0};
    char dir_name[256];
    sprintf(dir_name, "Client_%d", client_pid);
    mkdir(dir_name, 0755);
    // Loop that reads commands from the clien
    // Read a command from the client
    while (1)
    {
        if (read(client_fd_read, buffer, sizeof(buffer)) > 0)
        {
            // Process the command
            if (strcmp(buffer, "quit") == 0)
            {
                write(client_fd_write, "Client is exiting\n", 19);
                write(client_fd_write, "bye..", 6);
                close(client_fd_write);
                break;
            }
            if (comments(buffer, client_fd_write, server, server_dir_name, client_pid) == 0)
                continue;
            memset(buffer, 0, sizeof(buffer));
        }
        else
        {
            // printf("Client disconnected EXIT\n");
            break;
        }
    }
    memset(buffer, 0, sizeof(buffer));
    num_clients--;
    close(client_fd_write);
    close(client_fd_read);
    // printf("Client disconnected\n");
    sprintf(buffer, "Client disconnected with PID: %d\n", client_pid);
    printf("%s", buffer);
    write_log(buffer);
    kill(getppid(), SIGUSR1);
}
int open_read_fifo(int client_pid)
{
    char client_fifo_read[256] = {0};
    sprintf(client_fifo_read, CLIENT_FIFO_COMMANDS, (long)client_pid);
    mkfifo(client_fifo_read, 0666);
    int client_fd_read = open(client_fifo_read, O_RDONLY);
    // Store the client file descriptor
    if (client_fd_read == -1)
    {
        perror("open client fifo");
        exit(EXIT_FAILURE);
    }
    return client_fd_read;
}
int accept_client(int client_fd_write, int max_number_of_clients, Queue *client_queue, int server, char *server_dir_name)
{
    // Read the client's request from the server FIFO
    struct sigaction sa;
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);
    char buffer[256] = {0};
    memset(buffer, 0, sizeof(buffer));
    int server_fifo_fd = open(SERVER_FIFO, O_RDONLY);
    if (read(server_fifo_fd, buffer, sizeof(buffer)) > 0)
    {
        // Parse the client's PID, server's PID, and request type from the buffer
        long client_pid;
        long server_pid;
        char request_type[32];
        char *token = strtok(buffer, ":");
        // printf("REQUSET RECEIVED\n");
        sscanf(token, "%ld,%ld,%s", &client_pid, &server_pid, request_type);
        // printf("Received request from client %ld: %sa\n", client_pid, request_type);
        // printf("Server PID: %lda\n", server_pid);
        // Check if the server's PID in the request matches the actual PID of the server
        if ((int)server_pid != (int)server)
        {
            fprintf(stderr, "Server PID in the request does not match the actual PID of the server.\n");
            return 1;
        }
        int client_fd_read;
        // Create a new FIFO for this client
        char client_fifo_write[256] = {0};
        char client_fifo_read[256] = {0};
        sprintf(client_fifo_write, CLIENT_FIFO_NAME, client_pid);
        mkfifo(client_fifo_write, 0666);
        // int client_fd_read;
        if (client_fd_write == -1)
        {
            perror("open client fifo");
            exit(EXIT_FAILURE);
        }
        // Check the request type
        if (strcmp(request_type, "Connect") == 0)
        {
            // Handle "Connect" request
            if (num_clients < max_number_of_clients)
            {
                // Accept the client and fork a new process to handle it
                // Child process
                int client_fd_write = open(client_fifo_write, O_WRONLY);
                client_fd_read = open_read_fifo(client_pid);
                printf("Client PID %ld connected , Num_clients = %d\n", client_pid, num_clients);
                num_clients++;
                pid_t pid = fork();
                if (pid == 0)
                {
                    // Child process
                    serve_client(client_fd_write, client_fd_read, server, server_dir_name, client_pid);
                }
                else if (pid > 0)
                {
                    // Parent process
                    printf("Num clients after forking in parent process = %d\n", num_clients);
                    // Continue accepting new clients
                }
                else
                {
                    // Fork failed
                    perror("fork");
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                // Queue is full, inform the client to wait
                printf("Server is full. Client %ld is waiting for a spot.\n", client_pid);
                // Add client to the queue
                enqueue(client_queue, client_pid);
                // Inform client to wait
                char message[256];
                sprintf(message, "Server is full. Please wait for a spot to become available. Your position in the queue is %d.\n", client_queue->size);
                write(client_fd_write, message, strlen(message));
            }
        }
        else if (strcmp(request_type, "tryConnect") == 0)
        {
            // Handle "tryConnect" request
            if (num_clients < max_number_of_clients)
            {
                // Accept the client and fork a new process to handle it
                // Child process
                int client_fd_write = open(client_fifo_write, O_WRONLY);
                client_fd_read = open_read_fifo(client_pid);
                printf("Client PID %ld connected , Num_clients = %d\n", client_pid, num_clients);
                num_clients++;
                pid_t pid = fork();
                if (pid == 0)
                {
                    // Child process
                    serve_client(client_fd_write, client_fd_read, server, server_dir_name, client_pid);
                }
                else if (pid > 0)
                {
                    // Parent process
                    printf("Num clients after forking in parent process = %d\n", num_clients);
                    // Continue accepting new clients
                }
                else
                {
                    // Fork failed
                    perror("fork");
                    exit(EXIT_FAILURE);
                }
            }
            else
            { // not working
                // Queue is full, inform the client and let it leave without waiting
                printf("Server is full. Client %ld leaving without waiting.\n", client_pid);
                // Inform client to leave without waiting
                char message[256] = "Server is full. Please try again later.\n";
                write(client_fd_write, message, strlen(message));
                kill(client_pid, SIGTERM);
                // Close file descriptors and clean up
                close(client_fd_write);
                close(client_fd_read);
                unlink(CLIENT_FIFO_COMMANDS);
                unlink(CLIENT_FIFO_NAME);
                return 0;
                // how to kill this process
            }
        }
        else
        {
            // Invalid request type
            fprintf(stderr, "Invalid request type: %s\n", request_type);
            write(client_fd_write, "Invalid request type.\n", 23);
            // Close file descriptors and clean up
            close(client_fd_write);
            close(client_fd_read);
            unlink(CLIENT_FIFO_COMMANDS);
            unlink(CLIENT_FIFO_NAME);
            return 1;
        }
    }

    // After serving a client, check if there are clients waiting in the queue
    if (!isEmpty(client_queue) && num_clients < max_number_of_clients)
    {
        // Dequeue the first client from the queue
        long queued_client_pid = dequeue(client_queue);
        printf("\nDequeued client %ld from the queue\n", queued_client_pid);
        // Create FIFO names for the dequeued client
        char queued_client_fifo_write[256] = {0};
        char queued_client_fifo_read[256] = {0};
        sprintf(queued_client_fifo_write, CLIENT_FIFO_NAME, queued_client_pid);
        sprintf(queued_client_fifo_read, CLIENT_FIFO_COMMANDS, queued_client_pid);

        // Open the client FIFOs for writing and reading

        // // Fork a new process to handle the client
        // int queued_client_fd_read = open(queued_client_fifo_read, O_RDONLY);
        num_clients++;
        pid_t pid = fork();
        if (pid == 0)
        {
            // Child process
            int queued_client_fd_write = open(queued_client_fifo_write, O_WRONLY);
            int queued_client_fd_read = open(queued_client_fifo_read, O_RDONLY);
            serve_client(queued_client_fd_write, queued_client_fd_read, server, server_dir_name, queued_client_pid);
            exit(EXIT_SUCCESS);
        }
        else if (pid > 0)
        {
            // Parent process
            printf("Num clients after forking in parent process = %d\n", num_clients);
            // Continue accepting new clients
        }
        else
        {
            // Fork failed
            perror("fork");
            exit(EXIT_FAILURE);
        }
    }
    return 1;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <dirname> <max.#ofClients>\n", argv[0]);
        return 1;
    }
    int max_number_of_clients = atoi(argv[2]);
    char *dir_name = argv[1];

    struct sigaction sa;

    // Handle SIGINT
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Restart functions if interrupted by handler
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    // Handle SIGCHLD
    sa.sa_handler = handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);
    // Directory setup
    if (mkdir(dir_name, 0777) == -1)
    {
        if (errno != EEXIST)
        {
            perror("Error creating directory");
            return 1;
        }
    }

    if (chdir(dir_name) == -1)
    {
        perror("Failed to change directory");
        exit(1);
    }

    log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (log_fd == -1)
    {
        perror("Failed to open log file");
        exit(1);
    }

    char log_entry[100];
    sprintf(log_entry, "Server started. PID: %d", getpid());
    write_log(log_entry);

    setup_fifo();

    printf("Server started with PID %d...\n", getpid());
    printf("Waiting for clients...\n");
    // Array to store client file descriptors
    Queue *client_queue;
    client_queue = createQueue();
    int server_fifo_fd = open(SERVER_FIFO, O_RDONLY);
    int server_pid = getpid();
    if (server_fifo_fd == -1)
    {
        write_log("Failed to open server FIFO");
        exit(1);
    }
    printf("Accepting client...\n");

    while (1)
    {
        accept_client(server_fifo_fd, max_number_of_clients, client_queue, server_pid, dir_name);
        // printf("Num clients = %d\n", num_clients);
    }

    close(log_fd);
    close(server_fifo_fd);
    unlink(SERVER_FIFO);
    destroyQueue(client_queue);
    return 0;
}