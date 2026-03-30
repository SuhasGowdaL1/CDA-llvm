int sign_score(int x) {
    if (x > 0) {
        return 2;
    }
    if (x < 0) {
        return -2;
    }
    return 0;
}

int adjust_with_limit(int value, int limit) {
    int adjusted = value;

    while (adjusted > limit) {
        adjusted -= 3;
        if (adjusted % 5 == 0) {
            break;
        }
    }

    if (adjusted < 0) {
        adjusted = 0;
    }

    return adjusted;
}

int choose_bucket(int total) {
    switch (total) {
        case 0:
            return 0;
        case 1:
        case 2:
            return 1;
        case 3:
        case 4:
            return 2;
        default:
            return -1;
    }
}

int classify(int x, int y, int limit) {
    int total = 0;

    for (int i = 0; i < x; ++i) {
        if ((i % 2) == 0) {
            total += y;
        } else {
            total += sign_score(y - i);
        }
    }

    int adjusted = adjust_with_limit(total, limit);
    return choose_bucket(adjusted);
}
