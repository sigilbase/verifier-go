// Command differential runs verify.php and sigilbase-verify over every
// fixture in corpus/expected.json, in the recorded options, and fails on
// any difference in exit code or in the five results, or on any field of
// the --json document other than the implementation identity and free
// text. It also holds both to the recorded expectations. CI runs it as a
// required gate; a disagreement is a soundness bug in one of the two.
//
//	go run ./tools/differential -php php -go ./sigilbase-verify
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sigilbase/verifier-go/internal/difftest"
)

func main() {
	php := flag.String("php", "php", "php binary")
	phpArgs := flag.String("php-args", "", "leading arguments for php, space separated (an ini file, say)")
	verifyPHP := flag.String("verify-php", "reference/verify.php", "path to verify.php (the reference implementation mirrored under reference/)")
	goBinary := flag.String("go", "./sigilbase-verify", "path to the built sigilbase-verify")
	corpusPath := flag.String("corpus", "corpus/expected.json", "expected.json to drive the run")
	dir := flag.String("dir", ".", "working directory for both verifiers")
	flag.Parse()

	runner := &difftest.Runner{PHP: *php, VerifyPHP: *verifyPHP, GoBinary: *goBinary, Dir: *dir}
	if *phpArgs != "" {
		runner.PHPArgs = strings.Fields(*phpArgs)
	}
	corpus, err := difftest.LoadCorpus(*corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "differential:", err)
		os.Exit(2)
	}

	failed := 0
	report := func(name string, problems []string) {
		if len(problems) == 0 {
			fmt.Printf("agree   %s\n", name)
			return
		}
		failed++
		fmt.Printf("DIFFER  %s\n", name)
		for _, p := range problems {
			fmt.Printf("        %s\n", p)
		}
	}

	for _, name := range corpus.SortedFixtures() {
		exp := corpus.Fixtures[name]
		args := append(append([]string{}, corpus.OptionsFor(name)...), "corpus/"+name+".zip")
		php, err := runner.RunPHP(args...)
		if err != nil {
			report(name, []string{err.Error()})
			continue
		}
		goOut, err := runner.RunGo(args...)
		if err != nil {
			report(name, []string{err.Error()})
			continue
		}
		problems := difftest.Compare(php, goOut)
		for _, p := range difftest.CheckExpectation(php, exp) {
			problems = append(problems, "verify.php vs expected.json: "+p)
		}
		for _, p := range difftest.CheckExpectation(goOut, exp) {
			problems = append(problems, "sigilbase-verify vs expected.json: "+p)
		}
		report(name, problems)
	}

	for _, name := range corpus.SortedConsistency() {
		fx := corpus.Consistency[name]
		exp := &difftest.Expected{Result: fx.Result, Exit: fx.Exit}
		opts := corpus.ConsistencyOptionsFor(name)
		var forms [][]string
		if fx.Old != "" && fx.New != "" {
			forms = append(forms, append(append([]string{"--consistency"}, opts...), "corpus/"+fx.Old+".zip", "corpus/"+fx.New+".zip"))
		}
		if fx.Bundle != "" && fx.Root != "" {
			forms = append(forms, append(append([]string{"--consistency"}, opts...), "corpus/"+fx.Bundle+".zip", "--root", fx.Root, "--size", strconv.FormatInt(fx.Size, 10)))
		}
		for i, args := range forms {
			label := fmt.Sprintf("%s (form %d)", name, i+1)
			php, err := runner.RunPHP(args...)
			if err != nil {
				report(label, []string{err.Error()})
				continue
			}
			goOut, err := runner.RunGo(args...)
			if err != nil {
				report(label, []string{err.Error()})
				continue
			}
			problems := difftest.Compare(php, goOut)
			for _, p := range difftest.CheckExpectation(php, exp) {
				problems = append(problems, "verify.php vs expected.json: "+p)
			}
			for _, p := range difftest.CheckExpectation(goOut, exp) {
				problems = append(problems, "sigilbase-verify vs expected.json: "+p)
			}
			report(label, problems)
		}
	}

	if failed > 0 {
		fmt.Printf("\n%d fixture(s) differ. A disagreement between the two verifiers is a soundness bug in one of them.\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nevery fixture agrees")
}
