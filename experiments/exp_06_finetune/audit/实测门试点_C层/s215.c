#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NAME_LEN 32

typedef struct {
    char name[MAX_NAME_LEN];
    int id;
    double score;
} Student;

void print_student(Student *s) {
    printf("ID: %d\n", s->id);
    printf("Score: %.2f\n", s->score);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        return 1;
    }

    Student *stu = (Student *)malloc(sizeof(Student));
    if (!stu) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    strcpy(stu->name, argv[1]);
    stu->id = 1001;
    stu->score = 89.5;

    char *display_name = (char *)malloc(MAX_NAME_LEN + 1);
    if (!display_name) {
        free(stu);
        return 1;
    }

    sprintf(display_name, "Student: %s", stu->name);
    printf("%s\n", display_name);

    print_student(stu);

    free(display_name);
    free(stu);
    return 0;
}

