int sign_score(int x) {
    if (x > 0) {
        return 2;
    }
    if (x < 0) {
        return -2;
    }
    return 0;
}

int clamp_range(int value, int low, int high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

int compute_delta(int a, int b) {
    int raw = a - b;
    return clamp_range(raw, -10, 10);
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
        adjusted = sign_score(adjusted);
    }

    return clamp_range(adjusted, -12, limit + 4);
}

int score_penalty(int total) {
    int penalty = 0;
    if (total > 12) {
        penalty += 2;
    }
    if ((total % 3) == 0) {
        penalty += 1;
    }
    return clamp_range(penalty, 0, 3);
}

int choose_bucket(int total) {
    int penalized = total - score_penalty(total);

    switch (penalized) {
        case 0:
            return 0;
        case 1:
        case 2:
            return 1;
        case 3:
        case 4:
            return 2;
        default:
            return sign_score(penalized);
    }
}

int fold_sample(int total, int sample, int i, int limit) {
    int delta = compute_delta(sample, i);
    int bias = sign_score(sample - limit);

    if ((i % 2) == 0) {
        total += delta + bias;
    } else {
        total -= sign_score(delta);
    }

    return adjust_with_limit(total, limit);
}

int classify(int x, int y, int limit) {
    int total = 0;

    for (int i = 0; i < x; ++i) {
        int sample = y + i;
        total = fold_sample(total, sample, i, limit);
    }

    return choose_bucket(total);
}

int classify_series(int base, int stride, int rounds, int limit) {
    int aggregate = 0;

    for (int i = 0; i < rounds; ++i) {
        int x = base + i;
        int y = base + (i * stride);
        aggregate += classify(x, y, limit);
    }

    int adjusted = adjust_with_limit(aggregate, limit);
    return choose_bucket(adjusted);
}
