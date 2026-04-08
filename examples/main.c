typedef int (*fptr)(int);

typedef struct
{
    fptr f;
} S;

int A(int x) { return x + 1; }
int B(int x) { return x + 2; }

S arr[2];

void init(int x)
{
    arr[0].f = A;
    arr[1].f = B;

    if (x > 5)
        arr[0].f = B; // overwrite
}

int test(int x)
{
    init(x);
    return arr[x % 2].f(x);
}