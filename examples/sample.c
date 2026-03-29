int sign_score(int x) {
    int score = 0;

    if (x > 0) {
        score = 1;
    } else if (x < 0) {
        score = -1;
    }

    return score;
}
