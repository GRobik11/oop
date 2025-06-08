from typing_extensions import Self  # Импорт для Python < 3.11


def validate_coord(value: int, max_value: int) -> int:
    if not (0 <= value <= max_value):
        raise ValueError(f"Value must be in range [0, {max_value}]")
    return value


class Point2d:
    MAX_WIDTH = 800
    MAX_HEIGHT = 600

    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    @property
    def x(self) -> int:
        return self._x

    @x.setter
    def x(self, value: int):
        self._x = validate_coord(value, self.MAX_WIDTH)

    @property
    def y(self) -> int:
        return self._y

    @y.setter
    def y(self, value: int):
        self._y = validate_coord(value, self.MAX_HEIGHT)

    def __eq__(self, other) -> bool:
        return isinstance(other, Point2d) and self.x == other.x and self.y == other.y

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.x=}, {self.y=})"

    def __repr__(self) -> str:
        return self.__str__()


class Vector2d:
    __slots__ = ("x", "y")

    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    @classmethod
    def from_points(cls, start: Point2d, end: Point2d) -> Self:
        return cls(end.x - start.x, end.y - start.y)

    def __getitem__(self, index: int) -> int:
        return getattr(self, self.__slots__[index])

    def __setitem__(self, index: int, value: int):
        return setattr(self, self.__slots__[index], value)

    def __iter__(self):
        for value in self.__slots__:
            yield getattr(self, value)

    def __len__(self) -> int:
        return len(self.__slots__)

    def __eq__(self, other: Self) -> bool:
        return isinstance(other, Vector2d) and self.x == other.x and self.y == other.y

    def __abs__(self) -> float:
        return (self.x ** 2 + self.y ** 2) ** 0.5

    def __add__(self, other: Self) -> Self:
        return Vector2d(self.x + other.x, self.y + other.y)

    def __sub__(self, other: Self) -> Self:
        return Vector2d(self.x - other.x, self.y - other.y)

    def __mul__(self, scalar: int | float) -> Self:
        return Vector2d(int(self.x * scalar), int(self.y * scalar))

    def __truediv__(self, scalar: int | float) -> Self:
        return Vector2d(int(self.x / scalar), int(self.y / scalar))

    @classmethod
    def calc_dot(cls, first: Self, second: Self) -> int:
        return first.x * second.x + first.y * second.y

    def dot(self, other: Self) -> int:
        return self.calc_dot(self, other)

    @classmethod
    def calc_cross(cls, first: Self, second: Self) -> int:
        return first.x * second.y - first.y * second.x

    def cross(self, other: 'Vector2d') -> int:
        return self.calc_cross(self, other)

    @classmethod
    def calc_mixed(cls, first: Self, second: Self, three: Self) -> int:
        return first.x * (second.y * three.y) + first.y * (second.x * three.x)

    def mixed(self, first: Self, second: Self) -> Self:
        return self.calc_mixed(self, first, second)

    def __str__(self) -> str:
        return f"Vector2d({self.x=}, {self.y=})"

    def __repr__(self) -> str:
        return self.__str__()


# Демонстрация работы
if __name__ == "__main__":
    # Точки
    p1 = Point2d(10, 20)
    p2 = Point2d(30, 40)
    print(p1, p2, p1 == p2, "\n")  # False

    # Векторы
    v1 = Vector2d(2, 3)
    v2 = Vector2d.from_points(p1, p2)
    print(v2, "\n")  # Vector2d(x=20, y=20)

    # Операции
    print(v1 + v2)  # Vector2d(x=22, y=23)
    print(v1 * 2)   # Vector2d(x=4, y=6)
    print(v1.dot(v2))  # 2*20 + 3*20 = 100
    print(v1.cross(v2), "\n")  # 2*20 - 3*20 = -20

    print(v1)
    # Дандер методы
    diff = 5

    for i in range(len(v1)):
        v1[i] = v1[i] + diff

    print(v1)