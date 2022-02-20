#!/usr/bin/python3


import math
import mmap
import os


def _chunks(seq, n):
    return (seq[i:i+n] for i in range(0, len(seq), n))


def calculate_shannon_entropy(data):
    data = bytearray(data)
    length = len(data)

    occurrences = [0] * 256

    for byte in data:
        occurrences[byte] += 1

    entropy = 0.0
    for x in occurrences:
        if x:
            x = float(x) / length
            entropy -= x * math.log(x, 2)

    return entropy


class BarGraph:
    def __init__(self, name=None, data=None):
        if name is None and data is None:
            raise ValueError("Must supply name or data")
        if name is not None and data is not None:
            raise ValueError("Must supply only name or only data")

        self.__parse__(name, data)

    def __parse__(self, fname, data):
        if fname is not None:
            if os.stat(fname).st_size == 0:
                raise ValueError("The file is empty")

            try:
                with open(fname, "rb") as fp:
                    fileno = fp.fileno()

                    if hasattr(mmap, "MAP_PRIVATE"):
                        # unix
                        self.__data__ = mmap.mmap(fileno, 0, mmap.MAP_PRIVATE)
                    else:
                        # windows
                        self.__data__ = mmap.mmap(fileno, 0, access=mmap.ACCESS_READ)
            except IOError as error:
                error_msg = f"{error}"
                error_msg = error_msg and (f"{error_msg}")
                raise Exception("Unable to access file '{fname}': {error_msg}")
        elif data is not None:
            self.__data__ = data

    @staticmethod
    def _set_color(n, text=" "):
        return f"\033[48;5;{n}m" + f"{text}" + "\033[0m"

    def _bar_colour(self, entropy):
        if 0 < entropy <= 0.50:
            return self._set_color(130)
        elif 0.50 < entropy <= 1.00:
            return self._set_color(166)
        elif 1.00 < entropy <= 1.25:
            return self._set_color(202)
        elif 1.25 < entropy <= 1.50:
            return self._set_color(208)
        elif 1.50 < entropy <= 1.75:
            return self._set_color(214)
        elif 1.75 < entropy <= 2.00:
            return self._set_color(220)
        elif 2.00 < entropy <= 2.25:
            return self._set_color(226)
        elif 2.25 < entropy <= 2.50:
            return self._set_color(22)
        elif 2.50 < entropy <= 2.75:
            return self._set_color(28)
        elif 2.75 < entropy <= 3.00:
            return self._set_color(34)
        elif 3.00 < entropy <= 3.50:
            return self._set_color(40)
        elif 3.50 < entropy <= 4.00:
            return self._set_color(46)
        elif 4.00 < entropy <= 4.15:
            return self._set_color(17)
        elif 4.15 < entropy <= 4.25:
            return self._set_color(18)
        elif 4.25 < entropy <= 4.35:
            return self._set_color(19)
        elif 4.35 < entropy <= 4.70:
            # plain text
            return self._set_color(20)
        elif 4.70 < entropy <= 4.95:
            return self._set_color(21)
        elif 4.95 < entropy <= 5.1:
            return self._set_color(93)
        elif 5.10 < entropy <= 5.40:
            # native
            return self._set_color(92)
        elif 5.40 < entropy <= 5.85:
            # native
            return self._set_color(91)
        elif 5.85 < entropy <= 6.25:
            # native
            return self._set_color(90)
        elif 6.15 < entropy <= 6.40:
            return self._set_color(89)
        elif 6.30 < entropy <= 6.45:
            return self._set_color(161)
        elif 6.45 < entropy <= 6.65:
            return self._set_color(162)
        elif 6.65 < entropy <= 6.80:
            return self._set_color(163)
        elif 6.80 < entropy <= 6.90:
            # packed
            return self._set_color(164)
        elif 6.90 < entropy <= 7.00:
            # packed
            return self._set_color(165)
        elif 7.00 < entropy <= 7.15:
            # packed
            return self._set_color(124)
        elif 7.15 < entropy <= 7.25:
            # packed
            # encrypted
            return self._set_color(160)
        elif entropy > 7.25:
            # encrypted
            return self._set_color(196)

    def build(self, X_AXIS=80, Y_AXIS=16, top_down=False):
        MIN_X_AXIS = 64

        if X_AXIS < MIN_X_AXIS:
            raise ValueError(f"X_AXIS must be greater than '{MIN_X_AXIS}'")
        elif X_AXIS % 8 != 0:
            raise ValueError("X_AXIS must be a multiple of '8'")
        elif Y_AXIS == 0:
            raise ValueError("Y_AXIS cannot be '0'")
        elif Y_AXIS % 8 != 0:
            raise ValueError("Y_AXIS must be a multiple of '8'")

        data = bytearray(self.__data__)

        # define minimum block size
        if 64 <= X_AXIS <= 80:
            MIN_BLOCK_SIZE = 128
        elif 88 <= X_AXIS <= 104:
            MIN_BLOCK_SIZE = 96
        elif 112 <= X_AXIS <= 160:
            MIN_BLOCK_SIZE = 64
        elif 168 <= X_AXIS <= 216:
            MIN_BLOCK_SIZE = 48
        elif X_AXIS >= 224:
            MIN_BLOCK_SIZE = 32

        # calculate block size
        for bars_per_group in [ i for i in range(1, X_AXIS+1) if X_AXIS % i == 0 ]:
            no_of_groups = X_AXIS/bars_per_group
            block_size = math.ceil(len(data)/no_of_groups)
            if block_size >= MIN_BLOCK_SIZE:
                break

        data_chunks = _chunks(data, block_size)

        # build bar graph
        bars = []
        for _ in range(int(no_of_groups)):
            data_chunk = data_chunks.__next__()
            entropy = calculate_shannon_entropy(data_chunk)
            for _ in range(int(bars_per_group)):
                bar_color = round(entropy * (Y_AXIS / 8))
                bar_empty = Y_AXIS - bar_color

                bar =  [" "] * bar_empty
                bar += [self._bar_colour(entropy)] * bar_color
                bars.append(bar)

        # build scale
        Y_COORDINATES = ["0", "1", "2", "3", "4", "5", "6", "7"]

        RANGE = []
        for i in range(len(Y_COORDINATES)-1, -1, -1):
            RANGE.extend([" "] * int((Y_AXIS/8)-1) + Y_COORDINATES[i:i+1])

        if top_down:
            SCALE = ([" "] * int((Y_AXIS/8)-1) + ["\u203E"]) * 8
        else:
            SCALE = ([" "] * int((Y_AXIS/8)-1) + ["_"]) * 8

        bars.insert(0, RANGE)
        bars.insert(1, SCALE)
        bars.append(SCALE)
        bars.append(RANGE)

        X_AXIS = range(X_AXIS+4)

        if top_down:
            Y_AXIS = range(Y_AXIS-1, -1, -1)
        else:
            Y_AXIS = range(Y_AXIS)

        graph = ""
        for i in Y_AXIS:
            for j in X_AXIS:
                graph += bars[j][i]
            graph += "\n"

        self.__graph__ = graph

    def display(self):
        print(self.__graph__)