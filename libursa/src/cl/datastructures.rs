macro_rules! hashset {
    ( $( $x:expr ),* ) => {
        {
            let mut set = ::std::collections::HashSet::new();
            $(
                set.insert($x);
            )*
            set
        }
    }
}

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {
        {
            let mut map = ::std::collections::HashMap::new();
            $(
                map.insert($key, $val);
            )*
            map
        }
    }
}

macro_rules! btreeset {
    ( $( $x:expr ),* ) => {
        {
            let mut set = ::std::collections::BTreeSet::new();
            $(
                set.insert($x);
            )*
            set
        }
    }
}

macro_rules! btreemap {
    ($( $key: expr => $val: expr ),*) => {
        {
            let mut map = ::std::collections::BTreeMap::new();
            $(
                map.insert($key, $val);
            )*
            map
        }
    }
}
