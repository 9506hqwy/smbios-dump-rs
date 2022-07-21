use proc_macro::TokenStream;
use quote::quote;
use std::str::FromStr;
use syn::{
    parse, Expr, Field, Fields, GenericArgument, Ident, ItemStruct, Lit, PathArguments, Type,
};

#[proc_macro_derive(SMBIOS, attributes(smbios))]
pub fn xdr_union(input: TokenStream) -> TokenStream {
    let ast: ItemStruct = parse(input).unwrap();

    let struct_name = ast.ident;

    let mut field_getters = vec![];
    let mut field_names = vec![];
    let mut field_ctors = vec![];
    if let Fields::Named(fields) = ast.fields {
        for field in &fields.named {
            let func_name = field.ident.as_ref().unwrap();
            field_names.push(func_name.clone());

            let ty = &field.ty;
            let tydef = get_type_def(ty);
            let ret_ty = ty_ref(&tydef);
            let method = method_ref(func_name, &tydef);
            field_getters.push(quote! {
                pub fn #func_name(&self) -> #ret_ty {
                    #method
                }
            });

            if !tydef.optional {
                continue;
            }

            let ctor = field_ctor(field, &tydef);
            field_ctors.push(ctor);
        }
    }

    let struct_impl = quote! {
        impl #struct_name {
            #(#field_getters)*

            pub fn from_raw_table(raw: &RawSmbiosTable) -> Self {
                let table_ty = raw.table_ty;
                let length = raw.length;
                let handle = raw.handle;

                let mut body = raw.body.clone();

                #(#field_ctors)*

                #struct_name {
                    #(#field_names),*
                }
            }
        }
    };

    struct_impl.into()
}

#[derive(Debug)]
struct TypeDef {
    ident: Ident,
    array_length: i32,
    vector: bool,
    optional: bool,
    copy_trait: bool,
}

impl TypeDef {
    fn array(&self) -> bool {
        self.array_length > -1
    }

    fn enumerable(&self) -> bool {
        self.array() || self.vector
    }
}

fn ty_ref(tydef: &TypeDef) -> proc_macro2::TokenStream {
    let ret_ty = &tydef.ident;

    let ret_ty = if tydef.enumerable() {
        quote! { &[#ret_ty] }
    } else if is_string(ret_ty) {
        quote! { &str }
    } else if !tydef.copy_trait {
        quote! { &#ret_ty }
    } else {
        quote! { #ret_ty }
    };

    if tydef.optional {
        quote! { Option<#ret_ty> }
    } else {
        quote! { #ret_ty }
    }
}

fn method_ref(func_name: &Ident, tydef: &TypeDef) -> proc_macro2::TokenStream {
    if tydef.vector && tydef.optional {
        quote! { self.#func_name.as_deref() }
    } else if tydef.vector {
        quote! { self.#func_name.as_slice() }
    } else if tydef.array() && tydef.optional {
        quote! { self.#func_name.as_ref().map(|a| a.as_slice()) }
    } else if tydef.array() {
        quote! { self.#func_name.as_slice() }
    } else if is_string(&tydef.ident) && tydef.optional {
        quote! { self.#func_name.as_deref() }
    } else if is_string(&tydef.ident) {
        quote! { self.#func_name.as_str() }
    } else if !tydef.copy_trait && tydef.optional {
        quote! { self.#func_name.as_ref() }
    } else if !tydef.copy_trait {
        quote! { &self.#func_name }
    } else {
        quote! { self.#func_name }
    }
}

fn field_ctor(field: &Field, tydef: &TypeDef) -> proc_macro2::TokenStream {
    if is_u8(&tydef.ident) {
        let method = Ident::new("get_u8", proc_macro2::Span::call_site());
        field_ctor_number(field, tydef, &method, 1)
    } else if is_u16(&tydef.ident) {
        let method = Ident::new("get_u16_le", proc_macro2::Span::call_site());
        field_ctor_number(field, tydef, &method, 2)
    } else if is_u32(&tydef.ident) {
        let method = Ident::new("get_u32_le", proc_macro2::Span::call_site());
        field_ctor_number(field, tydef, &method, 4)
    } else if is_u64(&tydef.ident) {
        let method = Ident::new("get_u64_le", proc_macro2::Span::call_site());
        field_ctor_number(field, tydef, &method, 8)
    } else if is_i8(&tydef.ident) {
        let method = Ident::new("get_i8", proc_macro2::Span::call_site());
        field_ctor_number(field, tydef, &method, 1)
    } else if is_i16(&tydef.ident) {
        let method = Ident::new("get_i16_le", proc_macro2::Span::call_site());
        field_ctor_number(field, tydef, &method, 2)
    } else if is_i32(&tydef.ident) {
        let method = Ident::new("get_i32_le", proc_macro2::Span::call_site());
        field_ctor_number(field, tydef, &method, 4)
    } else if is_i64(&tydef.ident) {
        let method = Ident::new("get_i64_le", proc_macro2::Span::call_site());
        field_ctor_number(field, tydef, &method, 8)
    } else if is_string(&tydef.ident) {
        let func_name = &field.ident.as_ref().unwrap();

        quote! {
            let #func_name = if body.remaining() >= 1 {
                let idx = body.get_u8();
                raw.get_string_by_index(idx)
            } else {
                None
            };
        }
    } else {
        unimplemented!(
            "Not supported yet. Field `{}`",
            field.ident.as_ref().unwrap().to_string()
        );
    }
}

fn field_ctor_number(
    field: &Field,
    tydef: &TypeDef,
    method: &Ident,
    byte_size: usize,
) -> proc_macro2::TokenStream {
    let func_name = &field.ident.as_ref().unwrap();

    if tydef.array() {
        let length = tydef.array_length as usize;
        quote! {
            let #func_name = if body.remaining() >= (#length * #byte_size) {
                let mut arr = [0; #length];
                for idx in 0..#length {
                    arr[idx] = body.#method();
                }
                Some(arr)
            } else {
                None
            };
        }
    } else if tydef.vector {
        let length = get_attr_token(field, "length");
        quote! {
            let #func_name = if let Some(len) = #length {
                let len = len as usize;
                if body.remaining() >= (len * #byte_size) {
                    let mut v = vec![];
                    for _ in 0..len {
                        v.push(body.#method());
                    }
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            };
        }
    } else {
        quote! {
            let #func_name = if body.remaining() >= #byte_size {
                Some(body.#method())
            } else {
                None
            };
        }
    }
}

fn get_attr_token(field: &Field, name: &str) -> proc_macro2::TokenStream {
    for attr in field.attrs.iter().filter(|a| a.path.is_ident("smbios")) {
        for token in attr.clone().tokens.into_iter() {
            if let proc_macro2::TokenTree::Group(group) = token {
                let mut args = group.stream().into_iter();
                while let Some(arg) = args.next() {
                    if let proc_macro2::TokenTree::Ident(i) = arg {
                        if i == name {
                            if let Some(proc_macro2::TokenTree::Punct(op)) = args.next() {
                                if op.as_char() == '=' {
                                    match args.next() {
                                        Some(proc_macro2::TokenTree::Group(group)) => {
                                            let mut idents = vec![];
                                            for arg in group.stream().into_iter() {
                                                if let proc_macro2::TokenTree::Literal(value) = arg
                                                {
                                                    let arg_value =
                                                        value.to_string().replace('"', "");
                                                    let arg_ident = Ident::new(
                                                        &arg_value,
                                                        proc_macro2::Span::call_site(),
                                                    );
                                                    idents.push(arg_ident);
                                                }
                                            }

                                            // TODO:
                                            let i0 = &idents[0];
                                            let i1 = &idents[1];
                                            return quote! { #i0.map(|i| #i1.map(|j| i * j)).flatten()  };
                                        }
                                        Some(proc_macro2::TokenTree::Literal(value)) => {
                                            let arg_value = value.to_string().replace('"', "");
                                            let arg_ident = Ident::new(
                                                &arg_value,
                                                proc_macro2::Span::call_site(),
                                            );
                                            return quote! { #arg_ident };
                                        }
                                        _ => {
                                            // PASS
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    unimplemented!(
        "Need Attribute `{}` to Field `{}`",
        name,
        field.ident.as_ref().unwrap().to_string()
    );
}

fn get_array_len(len: &Expr) -> Option<i32> {
    if let Expr::Lit(expr) = len {
        if let Lit::Int(i) = &expr.lit {
            return i32::from_str(i.base10_digits()).ok();
        }
    }

    None
}

fn get_type_def(ty: &Type) -> TypeDef {
    match ty {
        Type::Array(a) => {
            let mut def = get_type_def(&a.elem);
            def.array_length = get_array_len(&a.len).unwrap();
            def
        }
        Type::Path(p) => match p.path.get_ident() {
            Some(i) => {
                let copy_trait = is_copy_trait(i);
                TypeDef {
                    ident: i.clone(),
                    array_length: -1,
                    vector: false,
                    optional: false,
                    copy_trait,
                }
            }
            _ => {
                let q_ty = &p.path.segments[0].ident;
                if let PathArguments::AngleBracketed(arg) = &p.path.segments[0].arguments {
                    if let GenericArgument::Type(arg_ty) = &arg.args[0] {
                        let mut def = get_type_def(arg_ty);

                        if is_vector(q_ty) {
                            def.vector = true;
                        }

                        if is_optional(q_ty) {
                            def.optional = true;
                        }

                        return def;
                    }
                }

                unimplemented!("Not supported yet. Type `{}`", q_ty.to_string());
            }
        },
        _ => {
            unimplemented!("Not supported yet.");
        }
    }
}

fn is_copy_trait(ident: &Ident) -> bool {
    matches!(
        ident.to_string().as_str(),
        "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64"
    )
}

fn is_optional(ident: &Ident) -> bool {
    is_type(ident, "Option")
}

fn is_string(ident: &Ident) -> bool {
    is_type(ident, "String")
}

fn is_i16(ident: &Ident) -> bool {
    is_type(ident, "i16")
}

fn is_i32(ident: &Ident) -> bool {
    is_type(ident, "i32")
}

fn is_i64(ident: &Ident) -> bool {
    is_type(ident, "i64")
}

fn is_i8(ident: &Ident) -> bool {
    is_type(ident, "i8")
}

fn is_u16(ident: &Ident) -> bool {
    is_type(ident, "u16")
}

fn is_u32(ident: &Ident) -> bool {
    is_type(ident, "u32")
}

fn is_u64(ident: &Ident) -> bool {
    is_type(ident, "u64")
}

fn is_u8(ident: &Ident) -> bool {
    is_type(ident, "u8")
}

fn is_vector(ident: &Ident) -> bool {
    is_type(ident, "Vec")
}

fn is_type(ident: &Ident, keyword: &str) -> bool {
    let ident_s = ident.to_string();
    ident_s.as_str() == keyword
}
