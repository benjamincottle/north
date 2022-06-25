" Vim syntax file
" Language: north

" Usage Instructions
" Put this file in .vim/syntax/north.vim
" and add in your .vimrc file the next line:
" autocmd BufRead,BufNewFile *.north set filetype=north

if exists("b:current_syntax")
  finish
endif

set iskeyword=a-z,A-Z,-,*,_,!,@
syntax keyword northTodos TODO FIXME NOTE

" Language keywords
syntax keyword northKeywords if else endif while do done exit syscall0 syscall1 syscall2 syscall3 syscall4 syscall5 syscall6 print include define or not and
syntax keyword northKeywords dup drop over swap rot dupnz min max 
syntax keyword northKeywords load store mem argc argv

" Comments
syntax region northCommentLine start=";" end="$"   contains=northTodos

" String literals
syntax region northString start=/\v"/ skip=/\v\\./ end=/\v"/ contains=northEscapes

" Char literals
syntax region northChar start=/\v'/ skip=/\v\\./ end=/\v'/ contains=northEscapes

" Escape literals \n, \r, ....
syntax match northEscapes display contained "\\[nr\"']"

" Number literals
syntax match northNumber "\v\d+"

" Operators
syntax match northOperator "\v\*"
syntax match northOperator "\v/"
syntax match northOperator "\v\+"
syntax match northOperator "\v-"
syntax match northOperator "\v\%"
syntax match northOperator "\v\=\="
syntax match northOperator "\v\!"
syntax match northOperator "\v\!\="
syntax match northOperator "\v\&"
syntax match northOperator "\v\|"
syntax match northOperator "\v\~"
syntax match northOperator "\v\^"
syntax match northOperator "\v\<"
syntax match northOperator "\v\>"
syntax match northOperator "\v\<\="
syntax match northOperator "\v\>\="
syntax match northOperator "\v\>\>"
syntax match northOperator "\v\<\<"
syntax match northOperator "\v#"

" Set highlights
highlight default link northTodos Todo
highlight default link northCommentLine Comment
highlight default link northString String
highlight default link northNumber Number
highlight default link northChar Character
highlight default link northEscapes SpecialChar
highlight default link northOperator Operator
highlight default link northKeywords Keyword
let b:current_syntax = "north"

