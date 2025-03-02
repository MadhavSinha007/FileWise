CC = g++
CFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lssl -lcrypto
SRC = encryptor.cpp
OBJ = encryptor.o
EXEC = encryptor

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJ) $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

keys:
	@echo "Generating RSA key pair..."
	@if [ ! -f private_key.pem ]; then openssl genpkey -algorithm RSA -out private_key.pem; fi
	@if [ ! -f public_key.pem ]; then openssl rsa -pubout -in private_key.pem -out public_key.pem; fi

encrypt: $(EXEC)
	@echo "Usage: make encrypt FILE=input.txt OUTPUT=output.enc"
	@./$(EXEC) encrypt $(FILE) $(OUTPUT)

decrypt: $(EXEC)
	@echo "Usage: make decrypt FILE=output.enc OUTPUT=decrypted.txt"
	@./$(EXEC) decrypt $(FILE) $(OUTPUT)

clean:
	rm -f $(OBJ) $(EXEC) *.enc *.txt
