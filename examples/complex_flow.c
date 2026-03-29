int classify(int x, int y) {
    int total = 0;

    for (int i = 0; i < x; ++i) {
        if ((i % 2) == 0) {
            total += y;
        } else {
            total -= 1;
        }
    }

    switch (total) {
        case 0:
            return 0;
        case 1:
        case 2:
            return 1;
        default:
            return -1;
    }
}
