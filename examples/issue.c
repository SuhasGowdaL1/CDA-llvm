void sys_config()
{
}
void sparse()
{
}
void pe_exit()
{
    for (int i = 0; i < 5; i++)
    {
        sparse();
    }
}

void pd_init()
{
    pe_exit();
    sys_config();
}
int main()
{
    pd_init();
    return 0;
}