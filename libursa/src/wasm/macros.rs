macro_rules! check_opt_reference {
    ($ref:ident, $thing:tt) => {
        if $ref.is_null() {
            None
        } else {
            let item: $thing = convert_from_js($ref)?;
            Some(item.0)
        }
    };
}

macro_rules! maperr {
    ($expr:expr) => {
        $expr.map_err(|e| e.to_string())?
    };
}

macro_rules! finalize {
    ($expr:expr) => {
        $expr.0.finalize().map_err(|e| e.to_string())?
    };
}
