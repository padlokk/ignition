# FEATURES_MATH - Mathematical Operations

RSB math package provides comprehensive mathematical operations organized into specialized packages, from basic arithmetic to advanced expression evaluation.

## Feature Flag: `math`

**Dependencies**: None (standalone feature)

## Package Architecture (MODULE_SPEC compliant)

- `src/math/mod.rs` - Orchestrator and curated public surface
- `src/math/basic/` - Core arithmetic operations (add, subtract, sqrt, rounding)
- `src/math/integers/` - Integer-specific operations (gcd, lcm, prime, factorial)
- `src/math/expressions/` - **Advanced expression parser** with variables (moved from src/math.rs)
- `src/math/base/` - Number base conversions (hex, binary, octal, arbitrary base)
- `src/math/percentage/` - Percentage and ratio calculations
- `src/math/predicates/` - Boolean tests (even, odd, sign, modulo)
- `src/math/aggregators/` - List aggregations (min, max, avg, median, sum)
- `src/math/random/` - Random number generation with type support
- `src/math/macros.rs` - Module-owned macros for all packages

## 🔥 Expression Evaluation (expressions/)

**Advanced mathematical expression parser with variable support**

- `evaluate_expression(expr)` - Evaluates complex mathematical expressions
  - **Variable assignment**: `"result = x * 2 + 5"`
  - **Shorthand operators**: `"counter += 10"`, `"value *= 2"`, `"sum /= 4"`
  - **Proper operator precedence**: `"2 + 3 * 4"` = 14 (not 20)
  - **Parentheses support**: `"(2 + 3) * 4"` = 20
  - **Power operator**: `"2 ** 3"` = 8, `"base ** exp"`
  - **Variable resolution**: Integrates with global context via `get_var()/set_var()`
  - **Floating-point numbers**: `"pi = 3.14159 * radius ** 2"`

### Expression Parser Implementation
- **Shunting Yard algorithm** for proper operator precedence
- **RPN (Reverse Polish Notation) evaluation** for efficiency
- **Token-based parsing** with comprehensive error handling
- **Variable interpolation** from RSB global state
- **Memory-safe evaluation** with bounds checking

## Basic Operations (basic/)
- `add(a, b)`, `subtract(a, b)`, `multiply(a, b)` - Core arithmetic
- `divide(a, b)` - Division with zero-check (returns Result)
- `power(base, exp)` - Exponentiation using powf
- `sqrt(n)` - Square root with negative number check
- `abs(n)` - Absolute value
- `min(a, b)`, `max(a, b)` - Minimum and maximum
- `round(n, places)`, `roundup(n, places)`, `rounddown(n, places)` - Precision rounding
- `floor(n)`, `ceil(n)` - Floor and ceiling functions
- `parse_number(text)` - Parse string to f64 with error reporting
- `calc(operation, a_str, b_str)` - Generic calculation with string I/O
- `eval_var(name)` - Evaluate a previously stored variable/expression from the math environment

## Integer Operations (integers/)
- `gcd(a, b)` - Greatest common divisor using Euclidean algorithm
- `lcm(a, b)` - Least common multiple
- `is_prime(n)` - Prime number test with optimized algorithm
- `factorial(n)` - Factorial with overflow protection (max n=20)
- `fibonacci(n)` - Generate nth Fibonacci number with saturation
- `factors(n)` - Find all factors of integer
- `sum_range(start, end)` - Sum integers in range (inclusive)

### Integer Arithmetic with Overflow Detection
- `int_add(a, b)` - Addition with overflow check
- `int_subtract(a, b)` - Subtraction with overflow check
- `int_multiply(a, b)` - Multiplication with overflow check
- `int_divide(a, b)` - Division with zero-check
- `int_power(base, exp)` - Exponentiation with overflow protection
- `int_parse(text)` - Parse string to integer with error reporting
- `int_calc(operation, a_str, b_str)` - Generic integer calculation with string I/O

## Base Conversion Operations (base/)
- `to_hex(n)`, `to_hex_upper(n)` - Convert to lowercase/uppercase hexadecimal
- `to_binary(n)`, `to_octal(n)` - Convert to binary/octal representation
- `from_hex(str)`, `from_binary(str)`, `from_octal(str)` - Parse from common bases
- `to_base(n, base)`, `from_base(str, base)` - Generic base conversion (base 2-36)
- `base_convert(str, from_base, to_base)` - Direct base-to-base conversion

## Percentage Operations (percentage/)
- `percent_of(total, percent)` - Calculate percentage of a value
- `percent_change(original, new)` - Calculate percentage change
- `ratio(numerator, denominator)` - Calculate ratio with zero-check
- `percentage_to_decimal(percent)`, `decimal_to_percentage(decimal)` - Conversions

## Predicate Operations (predicates/)
- `is_even(n)`, `is_odd(n)` - Even/odd number tests
- `modulo(a, b)` - Modulo operation with zero-check
- `sign(n)` - Get sign of number (-1, 0, 1)
- `same_sign(a, b)` - Check if two numbers have same sign
- `is_positive(n)`, `is_negative(n)`, `is_zero(n)` - Sign predicates

## Aggregator Operations (aggregators/)
- `min_list(numbers)`, `max_list(numbers)` - Find min/max in list
- `sum_list(numbers)` - Sum all numbers in list
- `avg(numbers)`, `mean(numbers)` - Calculate average/mean
- `median(numbers)` - Calculate median with automatic sorting

## Random Operations (random/)
- `random_range(min, max)` - Random float in range
- `random_int_range(min, max)` - Random integer in range
- `random_list_float(count, min, max)` - Generate list of random floats
- `random_list_int(count, min, max)` - Generate list of random integers
- `random_list_bool(count)` - Generate list of random booleans
- `random_list_string(type, count, range)` - **Powerful string-based random list generator**

## 🎯 Comprehensive Macro Interface

Logging & Errors
- Math macros report recoverable errors (e.g., divide by zero, parse failures) via the core logger `utils::stderrx("error", msg)` to keep default builds feature‑neutral. Optional visual macros can be used by importing them explicitly when compiling with visuals.

### Expression Macros
```rust
math!("result = x * 2 + 5");     // Advanced expression evaluation
math!("counter += 10");          // Shorthand assignment
math!("area = 3.14 * r ** 2");   // Complex expressions with variables
calc!("+", "5", "3");            // Generic calculator: "8"
int_calc!("gcd", "48", "18");    // Integer calculator: "6"
```

### Basic Operation Macros
```rust
add!(5.0, 3.0);           // 8.0
subtract!(10.0, 3.0);     // 7.0
multiply!(4.0, 5.0);      // 20.0
divide!(10.0, 2.0);       // 5.0 (handles division by zero gracefully)
power!(2.0, 3.0);         // 8.0
sqrt!(16.0);              // 4.0 (handles negative input)
min!(5.0, 3.0);           // 3.0
max!(5.0, 3.0);           // 5.0
round!(3.14159, 2);       // 3.14
roundup!(3.14159, 2);     // 3.15 (always rounds up)
rounddown!(3.14159, 2);   // 3.14 (always rounds down)
floor!(3.7);              // 3.0
ceil!(3.2);               // 4.0
```

### Integer Function Macros
```rust
gcd!(48, 18);             // 6
lcm!(4, 6);               // 12
is_prime!(17);            // true
factorial!(5);            // Ok(120)
fibonacci!(10);           // 55
```

### Base Conversion Macros
```rust
to_hex!(255);             // "ff"
to_hex_upper!(255);       // "FF"
to_binary!(8);            // "1000"
to_octal!(64);            // "100"
from_hex!("FF");          // 255
from_binary!("1000");     // 8
to_base!(100, 36);        // "2s" (base 36)
from_base!("2s", 36);     // 100
base_convert!("FF", 16, 2); // "11111111" (hex to binary)
```

### Percentage Macros
```rust
percent_of!(250, 20);     // 50.0 (20% of 250)
percent_change!(100, 150); // 50.0 (50% increase)
ratio!(16, 9);            // 1.777... (16:9 aspect ratio)
```

### Predicate Macros
```rust
even!(8);                 // true
odd!(7);                  // true
modulo!(10, 3);           // 1
sign!(-5);                // -1
same_sign!(5, 3);         // true
```

### Aggregator Macros
```rust
let numbers = vec![1.0, 2.0, 3.0, 4.0, 5.0];
avg!(&numbers);           // 3.0
mean!(&numbers);          // 3.0 (alias for avg)
median!(&numbers);        // 3.0
min_list!(&numbers);      // 1.0
max_list!(&numbers);      // 5.0
sum_list!(&numbers);      // 15.0
```

### Random Macros (🔥 Powerful!)
```rust
random_range!(1.0, 10.0);          // 7.23 (random float)
random_int_range!(1, 100);         // 42 (random integer)

// The powerful random_list! macro with type support:
random_list!(3, "bool");           // "1,0,1"
random_list!(5, "int", "1:100");   // "23,67,89,12,45"
random_list!(4, "float", "0:1");   // "0.23,0.78,0.45,0.91"
```

## String-First RSB Design

All functions provide string-based interfaces for shell-like usage:

```rust
// Integer calculations with strings
int_calc("add", "42", "58");        // "100"
int_calc("gcd", "48", "18");        // "6"
int_calc("multiply", "7", "8");     // "56"

// Float calculations with strings
calc("divide", "10.5", "2.1");      // "5"
calc("power", "2", "8");            // "256"

// Random list generation (most powerful feature)
random_list_string("int", 5, Some("1:100"));     // "23,67,89,12,45"
random_list_string("float", 3, Some("0.0:1.0")); // "0.23,0.78,0.45"
random_list_string("bool", 4, None);             // "1,0,1,0"
```

## Real-World Usage Examples

### Financial Calculations
```rust
let salary = 75000.0;
let raise_percent = 8.5;
let new_salary = salary + percent_of!(salary, raise_percent);
println!("New salary: ${:.2}", new_salary); // $81,375.00

let tax_rate = 22.0;
let tax_amount = percent_of!(new_salary, tax_rate);
println!("Tax owed: ${:.2}", tax_amount);
```

### Data Analysis
```rust
let scores = vec![85.5, 92.0, 78.5, 96.5, 88.0, 91.5, 84.0];
println!("Average: {:.2}", avg!(&scores));
println!("Median: {:.2}", median!(&scores));
println!("Range: {:.2} - {:.2}", min_list!(&scores), max_list!(&scores));

// Generate test data
let test_data = random_list!(100, "int", "70:100");
println!("Random test scores: {}", test_data);
```

### Expression-Based Calculations
```rust
rsb::global::set_var("radius", "7.5");
rsb::global::set_var("pi", "3.14159");

math!("area = pi * radius ** 2");          // Calculate area
math!("circumference = 2 * pi * radius");  // Calculate circumference
math!("diameter = radius * 2");            // Calculate diameter

println!("Circle area: {}", rsb::global::get_var("area"));           // "176.714"
println!("Circumference: {}", rsb::global::get_var("circumference")); // "47.124"
```

### Base Conversions for Programming
```rust
let rgb_red = 255;
println!("RGB Red in hex: #{}", to_hex_upper!(rgb_red));    // "#FF"
println!("In binary: {}", to_binary!(rgb_red));            // "11111111"

let permissions = from_octal!("755");  // Unix permissions
println!("Permissions: {}", permissions); // 493

// Convert between bases
let binary_data = "11111111";
let hex_equivalent = base_convert!(binary_data, 2, 16);
println!("Binary {} = Hex {}", binary_data, hex_equivalent); // "ff"
```

### Statistical Analysis
```rust
let daily_sales = vec![1250.0, 980.0, 1450.0, 1100.0, 1320.0];

let total = sum_list!(&daily_sales);
let average = avg!(&daily_sales);
let best_day = max_list!(&daily_sales);
let worst_day = min_list!(&daily_sales);

println!("Total sales: ${:.2}", total);
println!("Daily average: ${:.2}", average);
println!("Performance spread: ${:.2}", best_day - worst_day);

// Calculate percentage change from first to last day
let change = percent_change!(daily_sales[0], daily_sales[4]);
println!("Week-over-week change: {:.1}%", change);
```

### Random Data Generation
```rust
// Generate test datasets
let user_ages = random_list!(50, "int", "18:65");
let satisfaction_scores = random_list!(50, "float", "1.0:5.0");
let survey_responses = random_list!(50, "bool");

println!("User ages: {}", user_ages);
println!("Satisfaction: {}", satisfaction_scores);
println!("Yes/No responses: {}", survey_responses);

// Dice simulation
println!("Rolling 3 dice: {}", random_list!(3, "int", "1:6"));
```

## Advanced Features

### Package-Selective Imports
```rust
// Import only what you need
use rsb::math::percentage::*;  // Only percentage functions
use rsb::math::aggregators::*; // Only statistical functions
use rsb::math::random::*;      // Only random generators

// Or import everything
use rsb::math::*;
```

### Error Handling & Resilience
- **Overflow Protection**: Integer operations use checked arithmetic
- **Division by Zero**: Returns Result with descriptive error messages
- **Parse Errors**: Clear error messages for invalid input
- **Range Validation**: Functions validate input ranges where applicable
- **Graceful Degradation**: Macros return sensible defaults on error with logging
- **Memory Safety**: Uses saturating arithmetic and overflow checks throughout

### Global Context Integration
- **Variable Storage**: Expression evaluator integrates with RSB's global variable system
- **State Persistence**: Variables persist across expression evaluations
- **Parameter Expansion**: Seamless integration with RSB parameter expansion system
- **Shell-like Behavior**: Math operations feel natural in shell scripting context

## Architecture & Performance

- **MODULE_SPEC Compliance**: Clean separation of concerns across packages
- **Thin Macro Pattern**: All macros delegate to functions, zero business logic in macros
- **Performance Optimized**: Uses efficient algorithms (Euclidean GCD, optimized prime tests)
- **Cross-platform**: Pure Rust implementations, no platform-specific dependencies
- **Memory Efficient**: Zero-allocation string parsing where possible
- **Type Safety**: Strong typing with explicit conversions and error handling

## Testing Coverage

- **Comprehensive Sanity Tests**: Core functionality tests for all 8 packages
- **Visual UAT Tests**: Demonstrable outputs showing real-world usage
- **Edge Case Coverage**: Handles overflow, division by zero, invalid input
- **Performance Tests**: Large dataset handling and random generation
- **Integration Tests**: Cross-package functionality and global context integration

The RSB math module provides production-ready mathematical capabilities suitable for everything from simple calculations to complex data analysis and random data generation.

<!-- feat:math -->

_Generated by bin/feat.py --update-doc._

* `src/math/aggregators/mod.rs`
  - fn min_list (line 5)
  - fn max_list (line 13)
  - fn sum_list (line 21)
  - fn avg (line 25)
  - fn mean (line 33)
  - fn median (line 37)

* `src/math/base/mod.rs`
  - fn to_hex (line 5)
  - fn to_hex_upper (line 9)
  - fn to_binary (line 13)
  - fn to_octal (line 17)
  - fn from_hex (line 21)
  - fn from_binary (line 27)
  - fn from_octal (line 32)
  - fn to_base (line 37)
  - fn from_base (line 63)
  - fn base_convert (line 72)

* `src/math/basic/mod.rs`
  - fn add (line 7)
  - fn subtract (line 11)
  - fn multiply (line 15)
  - fn divide (line 19)
  - fn power (line 27)
  - fn sqrt (line 31)
  - fn abs (line 39)
  - fn min (line 43)
  - fn max (line 47)
  - fn round (line 51)
  - fn roundup (line 56)
  - fn rounddown (line 61)
  - fn floor (line 66)
  - fn ceil (line 70)
  - fn parse_number (line 74)
  - fn calc (line 80)
  - fn eval_var (line 108)

* `src/math/expressions/mod.rs`
  - fn evaluate_expression (line 216)

* `src/math/integers/mod.rs`
  - fn gcd (line 8)
  - fn lcm (line 19)
  - fn is_prime (line 28)
  - fn factors (line 49)
  - fn fibonacci (line 72)
  - fn factorial (line 92)
  - fn sum_range (line 106)
  - fn int_add (line 118)
  - fn int_subtract (line 124)
  - fn int_multiply (line 130)
  - fn int_divide (line 136)
  - fn int_power (line 145)
  - fn int_parse (line 152)
  - fn int_calc (line 159)

* `src/math/macros.rs`
  - pub use crate::math (line 4)
  - macro math! (line 7)
  - macro calc! (line 20)
  - macro int_calc! (line 27)
  - macro gcd! (line 34)
  - macro lcm! (line 41)
  - macro is_prime! (line 48)
  - macro factorial! (line 55)
  - macro fibonacci! (line 62)
  - macro add! (line 69)
  - macro subtract! (line 76)
  - macro multiply! (line 83)
  - macro divide! (line 90)
  - macro power! (line 103)
  - macro sqrt! (line 110)
  - macro min! (line 123)
  - macro max! (line 130)
  - macro round! (line 137)
  - macro roundup! (line 147)
  - macro rounddown! (line 157)
  - macro floor! (line 167)
  - macro ceil! (line 174)
  - macro to_hex! (line 181)
  - macro to_hex_upper! (line 188)
  - macro to_binary! (line 195)
  - macro to_octal! (line 202)
  - macro from_hex! (line 209)
  - macro from_binary! (line 222)
  - macro from_octal! (line 235)
  - macro to_base! (line 248)
  - macro from_base! (line 261)
  - macro base_convert! (line 274)
  - macro percent_of! (line 289)
  - macro percent_change! (line 296)
  - macro ratio! (line 303)
  - macro even! (line 318)
  - macro odd! (line 325)
  - macro modulo! (line 332)
  - macro sign! (line 345)
  - macro same_sign! (line 352)
  - macro min_list! (line 361)
  - macro max_list! (line 368)
  - macro avg! (line 375)
  - macro mean! (line 382)
  - macro median! (line 389)
  - macro sum_list! (line 396)
  - macro random_range! (line 405)
  - macro random_int_range! (line 412)
  - macro random_list! (line 419)

* `src/math/mod.rs`
  - pub use basic::{abs, add, divide, max, min, multiply, power, sqrt, subtract} (line 53)
  - pub use basic::{calc, ceil, eval_var, floor, parse_number, round, rounddown, roundup} (line 54)
  - pub use integers::{factorial, factors, fibonacci, gcd, is_prime, lcm, sum_range} (line 57)
  - pub use expressions::evaluate_expression (line 63)
  - pub use base::{base_convert, from_base, from_binary, from_hex, from_octal, to_base} (line 66)
  - pub use base::{to_binary, to_hex, to_hex_upper, to_octal} (line 67)
  - pub use predicates::{is_even, is_negative, is_odd, is_positive, is_zero, modulo, same_sign, sign} (line 75)
  - pub use aggregators::{avg, max_list, mean, median, min_list, sum_list} (line 78)

* `src/math/percentage/mod.rs`
  - fn percent_of (line 5)
  - fn percent_change (line 9)
  - fn ratio (line 21)
  - fn percentage_to_decimal (line 29)
  - fn decimal_to_percentage (line 33)

* `src/math/predicates/mod.rs`
  - fn is_even (line 5)
  - fn is_odd (line 9)
  - fn modulo (line 13)
  - fn sign (line 21)
  - fn same_sign (line 31)
  - fn is_positive (line 35)
  - fn is_negative (line 39)
  - fn is_zero (line 43)

* `src/math/random/mod.rs`
  - fn random_range (line 24)
  - fn random_int_range (line 28)
  - fn random_list_float (line 32)
  - fn random_list_int (line 36)
  - fn random_list_bool (line 40)
  - fn random_list_string (line 44)

<!-- /feat:math -->
