/* 
	Copyright (C) 1987-2002 Free Software Foundation, Inc.
	portions Copyright (C) 2007 Alex deVries
	
	This is based on readline's filemap.c example, which is very useful.

*/

#include "afp.h"
#include <config.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <pwd.h>
#include <stdarg.h>
#include "afp_protocol.h"
#include "client_url.h"
#include "libafpclient_internal.h"
#include "server.h"
#include "midlevel.h"
#include "afpclient_log.h"

static unsigned int uam_mask;
static struct client client;
static char username[AFP_MAX_USERNAME_LEN];
static char password[AFP_MAX_PASSWORD_LEN];
static char volumename[AFP_VOLUME_NAME_LEN];
static char curdir[AFP_MAX_PATH];
static struct afp_url url;

#define DEFAULT_DIRECTORY "/"

static pthread_t process_thread;
static struct afp_server * server = NULL;
static struct afp_volume * vol= NULL;
#define ARG_LEN 1024
static char global_arg[ARG_LEN];

static void cmdline_unmount_volume(struct afp_volume * volume) 
{

	return;
}


static int com_help(char *);

/* A structure which contains information on the commands this program
   can understand. */

typedef struct {
	char *name;          /* User printable name of the function. */
	rl_icpfunc_t *func;  /* Function to call to do the job. */
	char *doc;           /* Documentation for this function.  */
	int thread;          /* whether to launch as a new thread */
} COMMAND;



/* When non-zero, this global means the user is done using this program. */
static int done=0;


/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
char *
stripwhite (string)
     char *string;
{
  char *s, *t;

  for (s = string; whitespace (*s); s++)
    ;
    
  if (*s == 0)
    return (s);

  t = s + strlen (s) - 1;
  while (t > s && whitespace (*t))
    t--;
  *++t = '\0';

  return s;
}

/* **************************************************************** */
/*                                                                  */
/*                  Interface to Readline Completion                */
/*                                                                  */
/* **************************************************************** */

static char *command_generator PARAMS((const char *, int));

/* Attempt to complete on the contents of TEXT.  START and END bound the
   region of rl_line_buffer that contains the word to complete.  TEXT is
   the word to complete.  We can use the entire contents of rl_line_buffer
   in case we want to do some simple parsing.  Return the array of matches,
   or NULL if there aren't any. */
static char ** fileman_completion (const char *text, 
	int start, int end)
{
	char **matches = NULL;

	/* If this word is at the start of the line, then it is a command
	to complete.  Otherwise it is the name of a file in the current
	directory. */
	if (start == 0)
	matches = rl_completion_matches (text, command_generator);

	return (matches);
}

/* Tell the GNU Readline library how to complete.  We want to try to complete
   on command names if this is the first word in the line, or on filenames
   if not. */
static void initialize_readline ()
{
	  /* Allow conditional parsing of the ~/.inputrc file. */
	  rl_readline_name = "afpfsd";

	  /* Tell the completer that we want a crack first. */
	  rl_attempted_completion_function = fileman_completion;
}


/* Return non-zero if ARG is a valid argument for CALLER, else print
   an error message and return zero. */
static int valid_argument (char *caller, char *arg)
{
	if (!arg || !*arg) {
		fprintf (stderr, "%s: Argument required.\n", caller);
		return (0);
	}

	return (1);
}

static int get_server_path(char * filename,char * server_fullname)
{
	if (filename[0]!='/') {
		if (strlen(curdir)==1) 
			snprintf(server_fullname,PATH_MAX,"/%s",filename);
		else
			snprintf(server_fullname,PATH_MAX,"%s/%s",curdir,filename);
	}
	return 0;
}

static int com_list (char * arg)
{
	if (!arg)
		arg = "";

	struct afp_file_info *filebase = NULL,*p,*prev;

	
	if (ml_readdir(vol,"/",&filebase)) goto error;

	for (p=filebase;p;) {
		printf("%s\n",p->name);
		prev=p;
		p=p->next;
		free(prev);
	}


	
	return 0;
error:
	return -1;
}

static int com_chmod(char * arg)
{
	unsigned int mode;
	char basename[PATH_MAX];
	char server_fullname[AFP_MAX_PATH];
	int ret;

	if (sscanf(arg,"%s %o",basename,mode)!=2) {
		printf("expecting format: chmod <privs> <filename>\n");
		return 0;
	}
	get_server_path(basename,server_fullname);

	ret=ml_chmod(vol,server_fullname,mode);
	return 0;
}


static int com_put(char *filename)
{
	int ret, amount_read;
	struct afp_file_info *fp;
	int offset=0;
#define PUT_BUFSIZE 1024
	char buf[PUT_BUFSIZE];
	int fd;
	char server_fullname[AFP_MAX_PATH];
	char * basename;
	uid_t uid;
	gid_t gid;

	/* FIXME find basename */
	basename=filename;

	get_server_path(basename,server_fullname);

	/* FIXME need a better way to get server's uid/gid */

	uid=getuid();
	gid=getgid();

	fd = open(filename,O_RDONLY);

	if (fd<0) {
		printf("Problem opening local file\n");
		perror("opening");
		goto error;
	}

	ret = ml_open(vol,server_fullname,O_CREAT | O_RDWR,&fp);

	printf("Sending %s\n",basename);

	if (ret<0) {
		printf("Problem opening file %s on server\n",basename);
		goto out;
	}

	while (1) {
		amount_read=read(fd,buf,PUT_BUFSIZE);
		if (amount_read<0) {
			perror("Reading");
			goto out;
		}
		if (amount_read==0) goto out;
		ret=ml_write(vol,server_fullname,buf,amount_read,
			offset,fp,uid,gid);
		offset+=amount_read;
		if (ret<0) {
			printf("IO error when writing to server\n");
			goto out;
		}
		printf(".\n");
	}

	printf("Wrote %d bytes in %d seconds\n",basename,12);
/* FIXME time */

out:
	close(fd);
	ml_close(vol,server_fullname,fp);

error:
	return 0;

}

static int retrieve_file(char * arg,int fd)
{
	int flags=O_RDONLY;
	int ret=0;
	struct afp_file_info * fp;
	char path[PATH_MAX];
	off_t offset = 0;
#define BUF_SIZE 1024
	size_t size = BUF_SIZE;
	char buf[BUF_SIZE];
	int eof;


	get_server_path(arg,path);

printf("viewing: %s\n",path);

	ret = ml_open(vol,path,flags,&fp);
	
	if (ret) {
		printf("Could not open %s\n",arg);
		goto out;
	}

	ret =1; /* to get the loop going */
	while (ret) 
	{
		bzero(buf,BUF_SIZE);
		ret = ml_read(vol,path,buf,size,offset,fp,&eof);
		if (ret<=0) goto out;
printf("fd: %d\n",fd);
		write(fd,buf,ret);
		offset+=ret;
		if (eof==1) goto out;
	}
out:

	ml_close(vol,path,fp);
	free(fp);

	printf("done!\n");
	return 0;
}

static int com_get (char *filename)
{
	int fd;

	printf("Getting file %s\n",filename);

	fd=open(filename,O_CREAT | O_TRUNC| O_RDWR);
printf("using fd: %d\n",fd);
	if (fd<0) {
		perror("Opening file\n");
		return 0;
	}
printf("using fd: %d\n",fd);

	retrieve_file(filename,fd);

	close(fd);


	return 0;
}

static int com_view (char * arg)
{
	retrieve_file(arg,0);
	return 0;
}

static int com_rename (char * arg)
{
  return (1);
}

static int com_stat (char *arg)
{	
	return (0);
}

static int com_delete (char *arg)
{
	return (1);
}




static int com_connect(char * a)
{
	char mesg[1024];
	unsigned int len=0;
	char hostname[AFP_HOSTNAME_LEN];
	struct afp_connection_request * conn_req;

#define BUFFER_SIZE 2048

	if (sscanf(a, "%s %s",&hostname, &volumename) !=2) {
		printf("usage: <servername>:<volumename>\n");
		return -1;
	}
	
	/* This will be freed up in the kickoff thread */
	conn_req = malloc(sizeof(struct afp_connection_request));

        bzero(conn_req, sizeof(struct afp_connection_request));

        conn_req->requested_version=31;
        conn_req->uam_mask=3; /* default_uams_mask(); */
        bcopy(&username,&conn_req->username,AFP_MAX_USERNAME_LEN);
        bcopy(&password,&conn_req->password,AFP_MAX_PASSWORD_LEN);
        bcopy(&hostname,&conn_req->hostname,255);
        conn_req->port=548;

	if ((server=afp_server_full_connect(&client, conn_req))==NULL) {
		goto error;
	}


	vol=malloc(sizeof(struct afp_volume));
	vol->server=server;
	bcopy(volumename,vol->name,AFP_VOLUME_NAME_LEN);

	afp_connect_volume(vol,server,mesg,&len,1024 );
	 {
		goto error;
	}

	free(conn_req);

	printf("Connected to %s\n",server->server_name);
	return NULL;
error:
	return vol;
}


static int com_pass(char * arg)
{
	if (strlen(global_arg)==0) {
		printf("You must specify a password\n");
		return -1;
	}

	strncpy(password,arg,AFP_MAX_PASSWORD_LEN);

	return 0;

}

static int com_user(char * arg)
{
	if (strlen(global_arg)==0) {
		printf("You must specify a user\n");
		return -1;
	}

	strncpy(username,global_arg,AFP_MAX_USERNAME_LEN);

	return 0;

}

/* Change to the directory ARG. */
static int com_cd (char *arg)
{
	
	/* To change directory, get a file list and grab the did. */
	return (0);
}

/* Print out the current working directory. */
static int com_pwd (char * ignore)
{
	return 0;
}

/* The user wishes to quit using this program.  Just set DONE non-zero. */
static int com_quit (char *arg)
{
	done = 1;
	return (0);
}



COMMAND commands[] = {
  { "connect", com_connect, "Connect to URL",1},
  { "user", com_user, "Set user to USER",0 },
  { "pass", com_pass, "Set password to PASS",0 },
  { "cd", com_cd, "Change to directory DIR",1 },
  { "chmod", com_chmod, "Change mode",1},
  { "delete", com_delete, "Delete FILE",1 },
  { "help", com_help, "Display this text",0 },
  { "?", com_help, "Synonym for `help'",0 },
  { "list", com_list, "List files in DIR",1 },
  { "ls", com_list, "Synonym for `list'",1 },
  { "pwd", com_pwd, "Print the current working directory",0 },
  { "quit", com_quit, "Quit",0 },
  { "rename", com_rename, "Rename FILE to NEWNAME",1 },
  { "stat", com_stat, "Print out statistics on FILE",1 },
  { "view", com_view, "View the contents of FILE",1 },
  { "get", com_get, "Retrieve the file FILENAME and store them locally",1 },
  { "put", com_put, "Send a file to the server",1 },
  { (char *)NULL, (rl_icpfunc_t *)NULL, (char *)NULL,0 }
};

/* Generator function for command completion.  STATE lets us know whether
   to start from scratch; without any state (i.e. STATE == 0), then we
   start at the top of the list. */
static char * command_generator (const char *text, int state)
{
	static int list_index, len;
	char *name;

	/* If this is a new word to complete, initialize now.  This includes
	saving the length of TEXT for efficiency, and initializing the index
	variable to 0. */
	if (!state) {
		list_index = 0;
		len = strlen (text);
	}

	/* Return the next name which partially matches from the command list. */
	while ((name = commands[list_index].name))
	{
		list_index++;

		if (strncmp (name, text, len) == 0)
			{
			  char *r;

			  r = malloc (strlen (name) + 1);
			  strcpy (r, name);
			  return (r);
			}
	}

	/* If no names matched, then return NULL. */
	return ((char *)NULL);
}

/* Print out help for ARG, or for all of the commands if ARG is
   not present. */
static int com_help (char *arg)
{
  register int i;
  int printed = 0;

  for (i = 0; commands[i].name; i++)
    {
      if (!*arg || (strcmp (arg, commands[i].name) == 0))
        {
          printf ("%s\t\t%s.\n", commands[i].name, commands[i].doc);
          printed++;
        }
    }

  if (!printed)
    {
      printf ("No commands match `%s'.  Possibilties are:\n", arg);

      for (i = 0; commands[i].name; i++)
        {
          /* Print in six columns. */
          if (printed == 6)
            {
              printed = 0;
              printf ("\n");
            }

          printf ("%s\t", commands[i].name);
          printed++;
        }

      if (printed)
        printf ("\n");
    }
  return (0);
}

/* Look up NAME as the name of a command, and return a pointer to that
   command.  Return a NULL pointer if NAME isn't a command name. */
static COMMAND * find_command (char *name)
{
	  int i;

	  for (i = 0; commands[i].name; i++)
	  	if (strcmp (name, commands[i].name) == 0)
			return (&commands[i]);

	  return ((COMMAND *)NULL);
}

/* Execute a command line. */
static int execute_line (char * line)
{
	int i;
	COMMAND *command;
	char *word;

	/* Isolate the command word. */
	i = 0;
	while (line[i] && whitespace (line[i]))
		i++;
	word = line + i;

	while (line[i] && !whitespace (line[i]))
		i++;

	if (line[i])
		line[i++] = '\0';

	command = find_command (word);

	if (!command) {
		fprintf (stderr, "%s: No such command.\n", word);
		return (-1);
	}

	/* Get argument to command, if any. */
	while (whitespace (line[i]))
		i++;

	word = line + i;

	/* Call the function. */

	if (command->thread) {
		pthread_create(&process_thread, NULL, 
			command->func, word);
	} else {
		command->func(word);
	}
	return 0;
}


static int cmdline_scan_extra_fds(int command_fd, fd_set *set, int *max_fd)
{
	char * line;
	char * s;

	if (FD_ISSET(command_fd,set)) {
		line = readline ("afp_client: ");

		if (!line) return 0;

		/* Remove leading and trailing whitespace from the line.
		Then, if there is anything left, add it to the history list
		and execute it. */
		s = stripwhite (line);
		strncpy(global_arg,s,ARG_LEN);

		if (*s) {
			add_history (s);
			execute_line (global_arg);
		}

		free (line);
	}

        return 0;

}

static void cmdline_forced_ending_hook(void)
{

}

static int cmdline_add_client(int fd)
{


	return 0;
}

static void cmdline_signal_main_thread(void)
{

}



int main(int argc, char *argv[]) 
{
	struct passwd * passwd;

	snprintf(curdir,PATH_MAX,"%s",DEFAULT_DIRECTORY);

	uam_mask=default_uams_mask();

	passwd = getpwuid(getuid());
	bzero(username,AFP_MAX_USERNAME_LEN);
	strncpy(username, passwd->pw_name,AFP_MAX_USERNAME_LEN);

	libafpclient.scan_extra_fds=&cmdline_scan_extra_fds;
	libafpclient.unmount_volume=&cmdline_unmount_volume;
	libafpclient.log_for_client=&stdout_log_for_client;
	libafpclient.forced_ending_hook=&cmdline_forced_ending_hook;
	libafpclient.add_client=&cmdline_add_client;
	libafpclient.signal_main_thread=&cmdline_signal_main_thread;

	if (init_uams()<0) return -1;

	initialize_readline ();	/* Bind our completer. */

	afp_main_loop(fileno(stdin));

	exit (0);
}


