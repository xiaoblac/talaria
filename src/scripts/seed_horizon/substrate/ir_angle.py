# Copyright 2026 reFuzz project author -------youngkk.
# Base for angles whose facts come from an IR scan and are HANDLER/CMD-keyed (value-defuse, pointer,
# fptr, container, ...). The subclass supplies writer_facts(SH)/reader_facts(SH) (its vocabulary);
# this base attributes them to VARIANTS via region membership — the shared step every IR angle needs.
# Angles whose facts are already variant-keyed (resource, from the syzkaller model) implement
# writers/readers directly and do NOT inherit this.
from substrate.coupling import attribute


class IRAngle:
    resource_scoped = True        # struct-state coupling needs a shared object -> same-resource cred applies
                                  # (override False for global-state, which couples across resources)

    def writers(self, ctx):
        fn, hc = self.writer_facts(ctx.SH)
        return attribute(fn, hc, ctx.func2var, ctx.hc2var, ctx.FUNC_HUB)

    def readers(self, ctx):
        fn, hc = self.reader_facts(ctx.SH)
        return attribute(fn, hc, ctx.func2var, ctx.hc2var, ctx.FUNC_HUB)
