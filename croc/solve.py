from pwn import *
from dataclasses import dataclass
from enum import Enum, IntEnum
from abc import abstractmethod, ABC
import re
import string


#  eof, symbol, lambda, dot, open_bracket, close_bracket
class TokenType(IntEnum):
    EOF = 0
    SYMBOL = 1
    LAMBDA = 2
    DOT = 3
    OPEN_BRACKET = 4
    CLOSE_BRACKET = 5


@dataclass
class Token:
    type: TokenType
    value: str


class ExpressionType(Enum):
    VARIABLE = "V"
    ABSTRACTION = "ABS"
    APPLICATION = "APP"


class Expression:
    def __init__(self, type: ExpressionType):
        self.type = type

    def __str__(self):
        if self.type == ExpressionType.VARIABLE:
            return self.name
        elif self.type == ExpressionType.ABSTRACTION:
            return "λ" + (str(self.parameter)) + "." + str(self.body)
        elif self.type == ExpressionType.APPLICATION:
            return "(" + str(self.left) + " " + str(self.right) + ")"
        else:
            return self.type


class Variable(Expression):
    def __init__(self, name: str):
        super().__init__(ExpressionType.VARIABLE)
        self.name = name

    def __eq__(self, other):
        return isinstance(other, Variable) and self.name == other.name


class Abstraction(Expression):
    def __init__(self, parameter: Variable, body: Expression):
        super().__init__(ExpressionType.ABSTRACTION)
        self.parameter = parameter
        self.body = body

    def __eq__(self, other):
        if isinstance(other, Abstraction):
            return self.parameter == other.parameter and self.body == other.body
        else:
            return False

    
class Application(Expression):
    def __init__(self, left: Expression, right: Expression):
        super().__init__(ExpressionType.APPLICATION)
        self.left = left
        self.right = right

    def __eq__(self, other):
        if isinstance(other, Application):
            return self.left == other.left and self.right == other.right
        else:
            return False


class Lexer:
    def __init__(self, data):
        self._data = data
        self._pos = 0
        self._size = len(data)

    def _allowed_symbol(self, c):
        # print(c)
        v = ord(c)
        return (v >= 0x61 and v <= 0x7a) or (v >= 0x41 and v <= 0x5a)

    def _nextToken(self):
        self._skip_whitespace()
        if self._pos > self._size:
            raise ValueError("No more input to consume")
        if self._pos == self._size:
            return Token(TokenType.EOF, "")
        cdata = self._data[self._pos]
        if cdata == "λ":
            self._pos += 1
            return Token(TokenType.LAMBDA, "") 
        elif cdata == ".":
            self._pos += 1
            return Token(TokenType.DOT, "")
        elif cdata == "(":
            self._pos += 1
            return Token(TokenType.OPEN_BRACKET, "")
        elif cdata == ")":
            self._pos += 1
            return Token(TokenType.CLOSE_BRACKET, "")
        else:
            symbol = ""
            while (self._pos < self._size):
                c = self._data[self._pos]
                if self._allowed_symbol(c):
                    symbol += c
                    self._pos += 1
                else:
                    break

            if len(symbol) == 0:
                raise ValueError("Invalid symbol")
            return Token(TokenType.SYMBOL, symbol)

    def _skip_whitespace(self):
        while self._pos < self._size:
            c = ord(self._data[self._pos])
            if c in [32, 9, 10, 13, 11, 12]:
                self._pos += 1
            else:
                return

    def tokenize(self):
        tokens = []
        while self._pos < self._size:
            tokens.append(self._nextToken())
        tokens.append(self._nextToken())
        return tokens


class Parser:
    def __init__(self, tokens):
        self._tokens = iter(tokens)
        self._current_token = next(self._tokens)

    def _token(self):
        return self._current_token

    def _advance(self):
        self._current_token = next(self._tokens)

    def _variable(self):
        assert self._token().type == TokenType.SYMBOL
        name = self._token().value
        self._advance()
        return Variable(name)

    def _eat(self, pred):
        assert self._token().type == pred
        self._advance()

    def _abstraction(self):
        assert self._token().type == TokenType.LAMBDA
        self._advance()
        var = self._variable()
        self._eat(TokenType.DOT)
        return Abstraction(var, self._expression()) 

    def _atom(self):
        if self._token().type == TokenType.OPEN_BRACKET:
            self._advance()
            exp = self._expression()
            self._eat(TokenType.CLOSE_BRACKET)
            return exp
        elif self._token().type == TokenType.SYMBOL:
            return self._variable()
        else:
            return None

    def _application(self):
        left = self._atom()
        while True:
            right = self._atom()
            if right is None:
                return left
            else:
                left = Application(left, right)

    def _expression(self):
        if self._token().type == TokenType.LAMBDA:
            return self._abstraction()
        else:
            return self._application()

    def parse(self):
        ast = self._expression()
        if self._token().type != TokenType.EOF:
            raise ValueError("Expected EOF")
        return ast


def get_ast(data):
    lexer = Lexer(data)
    tokens = lexer.tokenize()

    parser = Parser(tokens)
    return parser.parse()

IDENTITY_RAW = "(λa. a)"
IDENTITY = get_ast(IDENTITY_RAW)
IF = IDENTITY

TRUE_RAW = "(λa. (λb. a))"
TRUE = get_ast(TRUE_RAW)

FALSE_RAW = "(λa. (λb. b))"
FALSE = get_ast(FALSE_RAW)

Y_RAW = f"(λf. ((λx. f(λy. x(x)(y)))(λx. f(λy. x(x)(y)))))"
Y = get_ast(Y_RAW)

INC_RAW = "(λn. ((λa. (λb. (a)((n(a))(b))))))"
INC = get_ast(INC_RAW)
ADD_RAW = f"(λa. (λb. (((a)({INC_RAW}))(b))))"
ADD = get_ast(ADD_RAW)
MUL_RAW = f"(λa. (λb. (λc. a(b(c)))))"
MUL = get_ast(MUL_RAW)
POW = get_ast(f"(λa. (λb. (b(a))))")
DEC_RAW = f"(λn.(λf.(λx. n((λg.(λh. h(g(f)))))(λy. x)({IDENTITY_RAW}))))"
DEC = get_ast(DEC_RAW)
SUB_RAW = f"(λa.(λb. (((b)({DEC_RAW}))(a))))"
SUB = get_ast(SUB_RAW)

ISZERO_RAW = f"(λa. a(λb. {FALSE_RAW})({TRUE_RAW}))"
ISZERO = get_ast(ISZERO_RAW)

LT_RAW = f"(λa.(λb. {ISZERO_RAW} (({SUB_RAW} ({INC_RAW} (a)) b)) ))"
LT = get_ast(LT_RAW)



def APPLY1(f, x):
    return f"({f} ({x}))"

def APPLY2(f, x, y):
    return f"((({f}) ({x})) ({y}))"

def APPLY3(f, x, y, z):
    return f"(((({f}) ({x})) ({y})) ({z}))"


def INC_CALL(x):
    return APPLY1(INC_RAW, x)

def ADD_CALL(x, y):
    return APPLY2(ADD_RAW, x, y)
    
def MUL_CALL(x, y):
    return APPLY2(MUL_RAW, x, y)
    
def POW_CALL(x, y):
    return APPLY2(POW_RAW, x, y)

def DEC_CALL(x):
    return APPLY1(DEC_RAW, x)

def SUB_CALL(x, y):
    return APPLY2(SUB_RAW, x, y)

def DIFF_CALL(x, y):
    return ADD_CALL(SUB_CALL(x, y), SUB_CALL(y, x))

def ISZERO_CALL(x):
    return APPLY1(ISZERO_RAW, x)

def GTE_CALL(a, b):
    return ISZERO_CALL(SUB_CALL(b, a))

def LTE_CALL(a, b):
    return ISZERO_CALL(SUB_CALL(a, b))

def GT_CALL(a, b):
    return ISZERO_CALL(SUB_CALL(INC_CALL(b), a))

def LT_CALL(a, b):
    return ISZERO_CALL(SUB_CALL(INC_CALL(a), b))

def EQ_CALL(a, b):
    return AND_CALL(GTE_CALL(a, b), LTE_CALL(a, b))


def NOT_CALL(x):
    return f"((λb.(λx.(λy.(b y x)))) {x})"

def AND_CALL(x, y):
    return f"(((λx.(λy.(((x y) {FALSE_RAW})))) ({x})) ({y}))"

def NAND_CALL(x, y):
    return NOT_CALL(AND_CALL(x, y))

def OR_CALL(x, y):
    return f"(((λa.(λb. (a({TRUE_RAW})(b)))) ({x})) ({y}))"


ZERO_RAW = FALSE_RAW
ZERO = get_ast(ZERO_RAW)

ONE_RAW = IDENTITY_RAW
ONE = get_ast(ONE_RAW)

TWO_RAW = INC_CALL(ONE_RAW)
TWO = get_ast(TWO_RAW)

THREE_RAW = INC_CALL(TWO_RAW)
THREE = get_ast(THREE_RAW)

FOUR_RAW = INC_CALL(THREE_RAW)
FOUR = get_ast(FOUR_RAW)

FIVE_RAW = INC_CALL(FOUR_RAW)
FIVE = get_ast(FIVE_RAW)

SIX_RAW = INC_CALL(FIVE_RAW)
SIX = get_ast(SIX_RAW)

SEVEN_RAW = INC_CALL(SIX_RAW)
SEVEN = get_ast(SEVEN_RAW)

EIGHT_RAW = INC_CALL(SEVEN_RAW)
EIGHT = get_ast(EIGHT_RAW)

NINE_RAW = INC_CALL(EIGHT_RAW)
NINE = get_ast(NINE_RAW)

TEN_RAW = INC_CALL(NINE_RAW)
TEN = get_ast(TEN_RAW)

DIV = get_ast(f"({Y_RAW} (λf. (λa. (λb. (({LT_RAW} (a)) (b)) (λy. {ZERO_RAW}) ((λy.  ({INC_RAW} (((f) (({SUB_RAW} (a)) (b))) (b)  ))   ) ) {ZERO_RAW} ))))")

MOD = get_ast(f"({Y_RAW} (λf. (λa. (λb. (({LT_RAW} (a)) (b)) (λy. a) ((λy.  ((((f) (({SUB_RAW} (a)) (b))) (b)  ))   ) ) {ZERO_RAW} ))))")


def ADDLIST(l):
    result = ZERO
    for val in l:
        result = ADD_CALL(result, val)
    return result

def MULLIST(l):
    result = ONE
    for val in l:
        result = MUL_CALL(result, val)
    return result


ONEHUNDRED_RAW = MUL_CALL(TEN_RAW, TEN_RAW)
ONEHUNDRED = get_ast(ONEHUNDRED_RAW)


NOT_RAW = f"(λb.(λx.(λy.(b y x))))"
NOT = get_ast(NOT_RAW)

AND_RAW = f"(λx.(λy.(((x y) {FALSE_RAW}))))"
AND = get_ast(AND_RAW)


OR_RAW = f"(λa.(λb. (a({TRUE_RAW})(b))))"
OR = get_ast(OR_RAW)



INT_TO_NUM_MAP = {0: ZERO_RAW, 1: ONE_RAW, 2: TWO_RAW, 3: THREE_RAW, 4: FOUR_RAW, 5: FIVE_RAW, 6: SIX_RAW, 7: SEVEN_RAW, 8: EIGHT_RAW, 9: NINE_RAW}



def gexp(t):
    return Expression(t)


def GETNUM(x):
    assert type(x) == int and x >= 0 and x <= 999
    factors = [INT_TO_NUM_MAP[int(a)] for a in str(x).rjust(3, "0")]
    factors_products = zip(factors, [ONEHUNDRED_RAW, TEN_RAW, ONE_RAW])
    
    muld = [MUL_CALL(v, p) for v, p in factors_products]
    return get_ast(ADDLIST(muld))


AST_TYPEL = [(AND, gexp("AND")), (OR, gexp("OR")), (ZERO, gexp("0")), (ONE, gexp("1")), (TWO, gexp("2")), (THREE, gexp("3")), (FOUR, gexp("4")), (FIVE, gexp("5")), (SIX, gexp("6")), (SEVEN, gexp("7")), (EIGHT, gexp("8")), (NINE, gexp("9")), (TEN, gexp("10")), (DIV, gexp("DIV")), (MOD, gexp("MOD")), (IDENTITY, gexp("IDENTITY")), (MUL, gexp("MUL")), (TRUE, gexp("TRUE")), (FALSE, gexp("FALSE")), (INC, gexp("INC")), (ADD, gexp("ADD")), (DEC, gexp("DEC")), (SUB, gexp("SUB")), (ISZERO, gexp("ISZERO")), (LT, gexp("LT"))]

for i in range(20):
    AST_TYPEL.append((GETNUM(i), gexp(f"{i}")))



class Replacer:
    def __init__(self, ast: Expression):
        self._ast = ast

    def _replace(self, expression: Expression):
        for ae, typ in AST_TYPEL:
            if expression == ae:
                return typ

        if expression.type == ExpressionType.ABSTRACTION:
            return Abstraction(expression.parameter, self._replace(expression.body))
        elif expression.type == ExpressionType.APPLICATION:
            return Application(self._replace(expression.left), self._replace(expression.right))
        else:
            return expression


    def run(self):
        return self._replace(self._ast)


class Reducer:
    def __init__(self, ast: Expression):
        self._ast = ast

    def _reduce_apply2(self, expression):
        assert expression.type == ExpressionType.APPLICATION
            
        reduction_map = {"DIV": "/", "MOD": "%", "AND": "&&", "OR": "||", "ADD": "+", "MUL": "*", "SUB": "-"}
        for red in reduction_map.keys():
            if expression.left.type == ExpressionType.APPLICATION and expression.left.left.type == red:
                repl = reduction_map[red]
                return Expression(f"({str(self._reduce(expression.left.right))} {repl} {str(self._reduce(expression.right))})")

        return None 

    def _reduce_apply1(self, expression):
        assert expression.type == ExpressionType.APPLICATION
            
        reduction_map = {"ISZERO": "== 0"}
        for red in reduction_map.keys():
            if expression.left.type == red:
                repl = reduction_map[red]
                return Expression(f"({str(self._reduce(expression.right))} {repl})")

        return None         

    def _reduce(self, expression: Expression):
        if expression.type == ExpressionType.ABSTRACTION:
            return Abstraction(expression.parameter, self._reduce(expression.body))
        elif expression.type == ExpressionType.APPLICATION:
            # if (red_exp3 := self._reduce_apply3(expression)) is not None:
            #   return red_exp3
            if (red_exp2 := self._reduce_apply2(expression)) is not None:
                return red_exp2
            elif (red_exp1 := self._reduce_apply1(expression)) is not None:
                return red_exp1
            else:
                return Application(self._reduce(expression.left), self._reduce(expression.right))
        else:
            return expression

    def run(self):
        return self._reduce(self._ast)

    

def translate(x):
    return x.replace("🐊", "λ").replace("💀", ".").replace("🤓", "(").replace("😳", ")")


inp = open("input", "r").read()

# transform to "proper" lambda calculus
data = translate(inp)
print(data)
exit()

# create ast
ast = get_ast(data)

# get proper arithmetic like form
replacer = Replacer(ast)
replaced_ast = replacer.run()

reducer = Reducer(replaced_ast)
reduced = reducer.run()
# print(reduced)

# was to lazy to properly get the div/mod comparison results with the ast
# so i did with a shit regex instead

alph = string.ascii_lowercase[:24]

div_results = [(alph.index(a), int(v)) for a, v in re.findall(r"\(p([a-z]) \/ 2\) - (\d)\) == 0", str(reduced))]
mod_results = [(alph.index(a), int(v)) for a, v in re.findall(r"\(p([a-z]) % 2\) - (\d)\) == 0", str(reduced))]

div_results = sorted(div_results, key=lambda tpl: tpl[0])
mod_results = sorted(mod_results, key=lambda tpl: tpl[0])

div_results = [tpl[1] for tpl in div_results]
mod_results = [tpl[1] for tpl in mod_results]

results = list(zip(div_results, mod_results))

code = [(r*2 + m) for r, m in results]
code = "".join([str(a) for a in code])
print(code)
assert code == "102232931041240015210711"


p = remote("kitctf.me", 33333)
p.recvuntil(b"Code: ")
p.sendline(code.encode())
print(p.recvline().strip().decode())
p.close()
