package com.shy.aesrsa;

enum Algorithm {
    RSA("RSA"), AES("AES");
    Algorithm(String value){

    }
    public boolean is = true;
    public Algorithm is(boolean is) {
        this.is = is;
        return this;
    }
}
