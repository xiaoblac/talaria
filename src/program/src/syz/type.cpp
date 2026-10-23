// Implementation for refuzz/program/syz/type.hpp
//
// Out-of-line method bodies that need full Expression/Field types.

#include "refuzz/program/syz/type.hpp"

namespace refuzz::program::syz {

// ============================================================
// Type — TemplateName (mirror of prog.TypeCommon.TemplateName)
// ============================================================

std::string Type::template_name() const {
    auto pos = name_.find('[');
    if (pos == std::string::npos) return name_;
    return name_.substr(0, pos);
}

// ============================================================
// Field
// ============================================================

Field::Field()  = default;
Field::~Field() = default;

Field::Field(std::string name, const Type* type)
    : name_(std::move(name)), type_(type) {}

Field::Field(Field&& other) noexcept
    : name_(std::move(other.name_)),
      type_(other.type_),
      has_direction_(other.has_direction_),
      direction_(other.direction_),
      condition_(std::move(other.condition_)) {
    other.type_          = nullptr;
    other.has_direction_ = false;
    other.direction_     = Dir::kIn;
}

Field& Field::operator=(Field&& other) noexcept {
    if (this != &other) {
        name_          = std::move(other.name_);
        type_          = other.type_;
        has_direction_ = other.has_direction_;
        direction_     = other.direction_;
        condition_     = std::move(other.condition_);
        other.type_          = nullptr;
        other.has_direction_ = false;
        other.direction_     = Dir::kIn;
    }
    return *this;
}

void Field::set_condition(std::unique_ptr<Expression> c) {
    condition_ = std::move(c);
}

// ============================================================
// StructType / UnionType find_field
// ============================================================

const Field* StructType::find_field(std::string_view name) const {
    for (const Field& f : fields_) {
        if (f.name() == name) {
            return &f;
        }
    }
    return nullptr;
}

const Field* UnionType::find_field(std::string_view name) const {
    for (const Field& f : fields_) {
        if (f.name() == name) {
            return &f;
        }
    }
    return nullptr;
}

bool UnionType::is_conditional() const {
    return !fields_.empty() && fields_.front().condition() != nullptr;
}

// ============================================================
// Expression clone
// ============================================================

std::unique_ptr<Expression> ValueExpr::clone() const {
    auto p = std::make_unique<ValueExpr>();
    p->set_value(value_);
    p->set_path(path_);
    return p;
}

std::unique_ptr<Expression> BinaryExpression::clone() const {
    auto p = std::make_unique<BinaryExpression>();
    p->set_op(op_);
    if (left_)  p->set_left(left_->clone());
    if (right_) p->set_right(right_->clone());
    return p;
}

} // namespace refuzz::program::syz
