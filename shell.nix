{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    python310
    python310Packages.pandas
    python310Packages.numpy
    python310Packages.matplotlib
    python310Packages.seaborn
    python310Packages.scikit-learn
  ];

  shellHook = ''
    echo "Security Log Analyzer development environment"
    echo "Python version: $(python --version)"
    echo "Run 'python main.py data/sample_logs.log' to test the application"
  '';
}