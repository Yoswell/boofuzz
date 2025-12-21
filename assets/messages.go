package assets

import (
	"fmt"
	"os"
	"strings"
	"github.com/fatih/color"
)

var (
	// Definición de colores base del proyecto
	InfoColor     = color.New(color.FgBlue)
	ErrorColor    = color.New(color.FgRed)
	WarningColor  = color.New(color.FgYellow) // CORRECCIÓN: Ahora es Amarillo
	SuccessColor  = color.New(color.FgGreen)
	ProgressColor = color.New(color.FgBlue)
)

// PrintKeywordError muestra un mensaje de error limpio cuando no se encuentra el keyword
func PrintKeywordError(keywords []string, colorize bool) {
	fmt.Print("\n")
	
	keywordStr := strings.Join(keywords, ", ")
	
	if colorize {
		ErrorColor.Fprint(os.Stderr, "[error]")
		fmt.Fprintf(os.Stderr, " :: Keyword '%s' definido en wordlist, pero no encontrado en la petición.\n", keywordStr)
	} else {
		fmt.Fprintf(os.Stderr, "[error] :: Keyword '%s' definido en wordlist, pero no encontrado en la petición.\n", keywordStr)
	}
	
	fmt.Fprintln(os.Stderr, "  Por favor asegúrate de que el keyword aparece en la URL, cabeceras o datos POST.")
	fmt.Fprintln(os.Stderr, "  Ejemplos:")
	fmt.Fprintln(os.Stderr, "    URL: http://94.237.61.248:43041/FUZZ")
	fmt.Fprintln(os.Stderr, "    Cabecera: 'User-Agent: FUZZ'")
	fmt.Fprintln(os.Stderr, "    POST data: 'username=FUZZ&password=test'")
	
	os.Exit(1)
}

// PrintWarning permite imprimir advertencias con el color amarillo configurado
func PrintWarning(message string, colorize bool) {
	if colorize {
		WarningColor.Fprint(os.Stderr, "[warning]")
		fmt.Fprintf(os.Stderr, " :: %s\n", message)
	} else {
		fmt.Fprintf(os.Stderr, "[warning] :: %s\n", message)
	}
}