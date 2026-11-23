import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GradeBadge } from "@/components/report/grade-badge";
import { GRADE_STYLES } from "@/components/report/styles";
import type { Grade } from "@/lib/scanner/types";

const GRADES: Grade[] = ["A+", "A", "B", "C", "D", "E", "F"];

describe("GradeBadge", () => {
  it("annonce la note avec son contexte (« Note A+ ») et l'affiche en toutes lettres", () => {
    render(<GradeBadge grade="A+" />);

    const badge = screen.getByRole("img", { name: "Note A+" });
    expect(badge).toHaveTextContent("A+");
  });

  it.each(GRADES)("applique les couleurs propres à la note %s", (grade) => {
    render(<GradeBadge grade={grade} />);

    const badge = screen.getByRole("img", { name: `Note ${grade}` });
    for (const className of GRADE_STYLES[grade].split(" ")) {
      expect(badge).toHaveClass(className);
    }
  });

  it("donne une couleur différente à chaque note, du vert au rouge", () => {
    expect(new Set(Object.values(GRADE_STYLES)).size).toBe(GRADES.length);
    expect(GRADE_STYLES["A+"]).toContain("emerald");
    expect(GRADE_STYLES.A).toContain("green");
    expect(GRADE_STYLES.B).toContain("lime");
    expect(GRADE_STYLES.C).toContain("amber");
    expect(GRADE_STYLES.D).toContain("orange");
    expect(GRADE_STYLES.E).toContain("orange-700");
    expect(GRADE_STYLES.F).toContain("red");
  });

  it("propose trois tailles (moyenne par défaut)", () => {
    const { rerender } = render(<GradeBadge grade="B" size="sm" />);
    expect(screen.getByRole("img", { name: "Note B" })).toHaveClass("size-10");

    rerender(<GradeBadge grade="B" size="lg" />);
    expect(screen.getByRole("img", { name: "Note B" })).toHaveClass("size-24");

    rerender(<GradeBadge grade="B" />);
    expect(screen.getByRole("img", { name: "Note B" })).toHaveClass("size-14");
  });
});
