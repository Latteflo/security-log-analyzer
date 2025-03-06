{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    (python310.withPackages(ps: with ps; [
      pandas
      numpy
      matplotlib
      seaborn
      scikit-learn
    ]))
  ];

  shellHook = ''
    echo "Security Log Analyzer development environment"
    echo "Python version: $(python --version)"
    echo "All dependencies are provided directly by Nix"
    echo "Run 'python main.py data/sample_logs.log' to test the application"
  '';
}