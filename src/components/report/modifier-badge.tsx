// Le nombre signé est masqué aux lecteurs d'écran, qui lisent mal les signes (« −20 » devient
// parfois « 20 ») : ils reçoivent une phrase explicite, « pénalité de 20 points ».
import { describeModifier, formatModifier } from "./format";
import { modifierStyle } from "./styles";

export function ModifierBadge({ modifier }: { modifier: number }) {
  return (
    <span
      className={`inline-flex min-w-10 justify-center rounded-md px-1.5 py-0.5 font-mono text-xs font-semibold tabular-nums ring-1 ring-inset ${modifierStyle(modifier)}`}
    >
      <span aria-hidden="true">{formatModifier(modifier)}</span>
      <span className="sr-only">{`, ${describeModifier(modifier)}, `}</span>
    </span>
  );
}
