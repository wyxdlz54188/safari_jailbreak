TARGET   = stage1
SRC      = .
INC      = .
LIB      = lib
OBJ      = obj
DEP      = dep
GEN      = genesis.S

DEP_C    = $(patsubst $(SRC)/%.m,%,$(wildcard $(SRC)/*.m))
DEP_CXX  = $(patsubst $(SRC)/%.mm,%,$(wildcard $(SRC)/*.mm))
IGXX     = xcrun -sdk iphoneos clang++ -arch arm64

FLAGS   ?= -Wall -O3 -fobjc-arc -miphoneos-version-min=12.0 $(CFLAGS)
LFLAGS  ?= -Wl,-x -Wl,-dead_strip -flto 
LFLAGS  += -Wl,-exported_symbols_list,keep.txt
FILES   := $(addsuffix .o, $(addprefix $(OBJ)/c/, $(DEP_C))) $(addsuffix .o, $(addprefix $(OBJ)/c++/, $(DEP_CXX)))

.PHONY: all clean distclean

all: $(TARGET)

$(TARGET): $(FILES)
	$(IGXX) -o $@ $(FLAGS) $(GEN) $(FILES) $(LFLAGS)

$(OBJ)/c/%.o: $(SRC)/%.m | $(OBJ)/c
	$(IGXX) -c -o $@ $(FLAGS) -xobjective-c -std=gnu11 $< -I$(INC)

$(OBJ)/c++/%.o: $(SRC)/%.mm | $(OBJ)/c++
	$(IGXX) -c -o $@ $(FLAGS) -xobjective-c++ -std=gnu++14 $< -I$(INC)

$(OBJ)/c:
	mkdir -p $@

$(OBJ)/c++:
	mkdir -p $@

clean:
	rm -rf $(TARGET) $(OBJ)
