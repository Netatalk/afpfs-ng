#include <string.h>
#include <stdlib.h>

static char *afp_strings[] = { "No User Authent",
                               "Cleartxt Passwrd",
                               "Randnum Exchange",
                               "2-Way Randnum Exchange",
                               "DHCAST128",
                               "Client Krb v2",
                               "DHX2",
                               "Recon1",
                               NULL
                             };


int uam_string_to_bitmap(char * name)
{
    for (int i = 0; afp_strings[i] != NULL; i++)
        if (strcasecmp(name, afp_strings[i]) == 0) {
            return 1 << i;
        }

    return 0;
}

char *uam_bitmap_to_string(unsigned int bitmap)
{
    int max_index;

    for (max_index = 0; afp_strings[max_index] != NULL; max_index++);

    max_index--;

    for (int i = max_index; i >= 0; i--)
        if (bitmap & (1 << i)) {
            return afp_strings[i];
        }

    return NULL;
}
