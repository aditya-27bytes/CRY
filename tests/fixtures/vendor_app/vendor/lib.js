// Intentionally vulnerable vendor library
function parseData(userInput) {
    return eval("var obj = " + userInput);
}
