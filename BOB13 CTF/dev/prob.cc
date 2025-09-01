#include <iostream>
#include <ncurses.h>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <cstdint>
#include <openssl/sha.h>

// #define DEBUG

#ifdef DEBUG
    #define obfu() {} 
#else
    #define obfu() asm("backend-obfu")
#endif

#define SNAKE_SPEED 1000
#define WIDTH 100
#define HEIGHT 30
#define END_GOAL 101
#define FLAG_LENGTH 36

using namespace std;

uint64_t key = 0;

uint64_t fnv1a_hash64(uint64_t key) {
    obfu();
    const uint64_t FNV_OFFSET_BASIS = 0xcbf29ce484222325;
    const uint64_t FNV_PRIME = 0x100000001b3;

    uint64_t hash = FNV_OFFSET_BASIS;
    for (int i = 0; i < 8; ++i) {
        hash ^= (key & 0xFF);
        hash *= FNV_PRIME;
        key >>= 8;
    }
    return hash;
}

bool is_traced() {
    obfu();
    int a = 0;
    int b = 1;
    int c = a * b + a - b;
    c <<= 16;
    int d = 3;
    double f = 0.1212313212;
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1;
}

class Initializer {
    public:
        Initializer() {
            if (is_traced() == true) {
                key = 0xcbf29ce484222325;
            } else {
                key = 0x89cd31291d2aefa4;
            }
        }
};
Initializer initializer;

struct Position {
    int x, y;
};

// shift right
void func1(void *flag) {
    obfu();
    char *str = (char *)flag;
    int n = FLAG_LENGTH;
    
    if (n > 1) {
        char last_char = str[n - 1];
        for (int i = n - 1; i > 0; --i) {
            str[i] = str[i - 1];
        }
        str[0] = last_char;
    }
}

// shift left
void func2(void *flag) {
    obfu();
    char *str = (char *)flag;
    int n = FLAG_LENGTH;
    
    if (n > 1) {
        char first_char = str[0];
        for (int i = 0; i < n - 1; ++i) {
            str[i] = str[i + 1];
        }
        str[n - 1] = first_char;
    }
}

// xor odd index
void func3(void *flag) {
    obfu();
    char *str = (char *)flag;
    int n = FLAG_LENGTH;
    
    for (int i = 1; i < n; i += 2) {
        str[i] ^= 0xaa;
    }
}

// xor even index
void func4(void *flag) {
    obfu();
    char *str = (char *)flag;
    int n = FLAG_LENGTH;
    
    for (int i = 0; i < n; i += 2) {
        str[i] ^= 0x77;
    }
}

// flip even bits at odd indexes
void func5(void *flag) {
    obfu();
    char *str = (char *)flag;
    int n = FLAG_LENGTH;
    
    for (int i = 1; i < n; i += 2) {
        for (int bit = 0; bit < 8; bit += 2) {
            str[i] ^= (1 << bit);
        }
    }
}

// swap first last 16 bytes
void func6(void *flag) {
    obfu();
    char *str = (char *)flag;
    int n = FLAG_LENGTH;

    for (int i = 0; i < 16; ++i) {
        char temp = str[i];
        str[i] = str[n - 16 + i];
        str[n - 16 + i] = temp;
    }
}

void func7(void *flag) {
    obfu();
    char *str = (char *)flag;
    for (int i=0; i<10; i++) {
        for (int j=0; j<10; j++) {
            char c = str[i+j];
        }
    }
}

void func8(void *flag) {
    obfu();
    char *str = (char *)flag;
    str += 100;
    str += 0xff;
    for (int i=0; i<10; i++) {
        for (int j=0; j<10; j++) {
            str += i * 10 + j;
        }
    }
}

void calculate_sha256(const unsigned char* data, size_t length, unsigned char* hash_output) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data, length);
    SHA256_Final(hash_output, &sha256_ctx);
}

void print_hash(unsigned char* hash) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::endl;
}

bool check_hash(const unsigned char *flag) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char compare_table[] = {195, 250, 145, 240, 103, 238, 228, 158, 247, 47, 8, 135, 45, 25, 51, 74, 188, 192, 14, 122, 61, 112, 215, 234, 143, 98, 177, 219, 196, 232, 238, 203};
    calculate_sha256(flag, FLAG_LENGTH, hash);
    for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
        if (hash[i] != compare_table[i]) {
            return false;
        }
    }

    return true;
}

class SnakeGame {
private:
    int width, height;
    vector<Position> snake;
    vector<pair<void(*)(void *), int>> func_vector;

    Position food;
    int dx, dy;
    bool gameOver;
    bool is_wall_drawed;
    void (*func_table[8])(void*) = {0, };
    uint64_t offset_table[8] = {10047854, 13117077, 3601528, 7642688, 11506698, 13528110, 14714558, 10014866};
    uint8_t compare_table[FLAG_LENGTH + 1] = {0x61, 0x6c, 0x65, 0x63, 0x64, 0x66, 0x62, 0x66, 0x61, 0x64, 0x65, 0x62, 0x63, 0x67, 0x66, 0x64, 0x64, 0x65, 0x62, 0x67, 0x63, 0x62, 0x66, 0x6c, 0x62, 0x60, 0x63, 0x6c, 0x66, 0x61, 0x65, 0x64, 0x64, 0x67, 0x62, 0x6d};

public:
    SnakeGame(int w, int h) : width(w), height(h), dx(1), dy(0), gameOver(false) {
        obfu();
        initscr();
        clear();
        noecho();
        cbreak();
        curs_set(0);
        keypad(stdscr, TRUE);
        timeout(100);

        func_table[0] = reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func1) - 10047854);
        func_table[1] = reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func2) + 13117077);
        func_table[2] = reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func3) - 3601528);
        func_table[3] = reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func4) + 7642688);
        func_table[4] = reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func5) - 11506698);
        func_table[5] = reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func6) + 13528110);
        func_table[6] = reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func7) - 14714558);
        func_table[7] = reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func8) + 10014866);
        
        snake.push_back({w / 2, h / 2});
        placeFood();
    }

    ~SnakeGame() {
        endwin();
    }

    void placeFood() {
        obfu();
        srand(time(0));
        food.x = rand() % (width - 2) + 1;
        food.y = rand() % (height - 2) + 1;
    }

    void input() {
        obfu();
        int ch = getch();
        switch (ch) {
            case KEY_UP: if (dy == 0) { dx = 0; dy = -1; } break;
            case KEY_DOWN: if (dy == 0) { dx = 0; dy = 1; } break;
            case KEY_LEFT: if (dx == 0) { dx = -1; dy = 0; } break;
            case KEY_RIGHT: if (dx == 0) { dx = 1; dy = 0; } break;
            case 'q': gameOver = true; break;
        }
    }

    void update() {
        obfu();
        Position newHead = {snake[0].x + dx, snake[0].y + dy};

        if (newHead.x <= 0 || newHead.x >= width - 1 || newHead.y <= 0 || newHead.y >= height - 1) {
            gameOver = true;
            return;
        }

        for (size_t i = 1; i < snake.size(); i++) {
            if (snake[i].x == newHead.x && snake[i].y == newHead.y) {
                gameOver = true;
                return;
            }
        }

        if (newHead.x == food.x && newHead.y == food.y) {
            snake.push_back({0, 0});
            key = fnv1a_hash64(key);
            func_vector.emplace_back(func_table[key % 8], key % 8);

            placeFood();
        }

        for (size_t i = snake.size() - 1; i > 0; i--) {
            snake[i] = snake[i - 1];
        }
        snake[0] = newHead;
    }

    void draw() {
        obfu();
        clear();
        char sharp[2] = {0, };
        char asterisk[2] = {0, };
        char buf1[2] = {0, };
        char buf2[2] = {0, };

        sharp[0] = '#' - 32;
        sharp[0] += 32;
        asterisk[0] = '*' - 30;
        asterisk[0] += 30;
        buf1[0] = 'O' - 40;
        buf1[0] += 40;
        buf2[0] = 'o' - 80;
        buf2[0] += 80;

        for (int i = 0; i < width; i++) {
            mvprintw(0, i, sharp);
            mvprintw(height - 1, i, sharp);
        }
        for (int i = 0; i < height; i++) {
            mvprintw(i, 0, sharp);
            mvprintw(i, width - 1, sharp);
        }

        mvprintw(food.y, food.x, asterisk);

        for (size_t i = 0; i < snake.size(); i++) {
            mvprintw(snake[i].y, snake[i].x, i == 0 ? buf1 : buf2);
        }

        refresh();
    }

    void run() {
        obfu();
        while (!gameOver) {
            input();
            update();
            draw();
            usleep(SNAKE_SPEED);

            if (snake.size() == END_GOAL) {
                gameOver = true;
                endwin();
                clear();
                string input;
                cin >> input;
                char flag[FLAG_LENGTH + 1] = {0, };
                for (int i=0; i<FLAG_LENGTH; i++) {
                    flag[i] = input.c_str()[i];
                }
                
                if(check_hash(reinterpret_cast<const unsigned char *>(flag)) == false) {
                    exit(0);
                }

                for (const auto& [func, offset] : func_vector) {
                    if (offset % 2 == 0) {
                        reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func) + offset_table[offset])(static_cast<void*>(const_cast<char*>(flag)));
                    }
                    else {
                        reinterpret_cast<void(*)(void*)>(reinterpret_cast<uintptr_t>(func) - offset_table[offset])(static_cast<void*>(const_cast<char*>(flag)));
                    }
                }

                bool is_same = true;
                for (int i=0; i<FLAG_LENGTH; i++) {
                    if ((uint8_t)(flag[i] & 0xff) != (uint8_t)(compare_table[i]&0xff)) {
                        is_same = false;
                        break;
                    }
                }

                if (is_same) {
                    cout << "flag: " << "FLAG{" << input << "}" << endl;
                }
                else {
                    cout << "fail" << endl;
                }
                exit(0);
            }
        }

        refresh();
        sleep(2);
    }
};

void checkWindowSize(int width, int height) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    if (w.ws_col < width || w.ws_row < height) {
        endwin();
        printf("Terminal window is too small! Required: %d x %d\n", width, height);
        printf("Current size: %d x %d\n", w.ws_col, w.ws_row);
        exit(1);
    }
}

int main() {
    checkWindowSize(WIDTH, HEIGHT);
    SnakeGame game(WIDTH, HEIGHT);
    game.run();
    return 0;
}
