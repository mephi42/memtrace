// Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.
#ifndef IDENTIFIER_H_
#define IDENTIFIER_H_

#define DEFINE_IDENTIFIER(Identifier, ValueType)                         \
  struct Identifier {                                                    \
    using value_type = ValueType;                                        \
                                                                         \
    bool operator==(Identifier rhs) const { return value == rhs.value; } \
    bool operator!=(Identifier rhs) const { return value != rhs.value; } \
    bool operator<(Identifier rhs) const { return value < rhs.value; }   \
    value_type hash() const { return value; }                            \
                                                                         \
    value_type value = 0;                                                \
  }

#endif  // IDENTIFIER_H_
