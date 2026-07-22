use super::*;

impl IndexFacade {
    /// Find symbol definitions. Routes per [`RoutingTable`].
    pub async fn definitions(&mut self, symbol: &str, repo: &Path) -> Result<Vec<Symbol>> {
        let value = self
            .first_successful_backend(Query::Definitions, "definitions", symbol, |backend| {
                definition_call(backend, symbol, repo)
            })
            .await?;
        Ok(symbol_matches(&value))
    }

    /// Find symbol references (callers, usages). Routes per
    /// [`RoutingTable`].
    pub async fn references(&mut self, symbol: &str, repo: &Path) -> Result<Vec<Symbol>> {
        let value = self
            .first_successful_backend(Query::References, "references", symbol, |backend| {
                references_call(backend, symbol, repo)
            })
            .await?;
        Ok(symbol_matches(&value))
    }

    /// Methods that call the named function. Routes per [`RoutingTable`].
    /// Tries clang first when (file, line, column) is supplied; otherwise
    /// falls through to the cpg backend's name-based query.
    pub async fn callers_of(
        &mut self,
        symbol: &str,
        position: Option<&FilePosition>,
    ) -> Result<Value> {
        self.first_successful_backend(Query::CallersOfFunction, "callers_of", symbol, |backend| {
            callers_call(backend, symbol, position)
        })
        .await
    }

    /// Methods called by the named function. Routes per [`RoutingTable`].
    pub async fn callees_of(
        &mut self,
        symbol: &str,
        position: Option<&FilePosition>,
    ) -> Result<Value> {
        self.first_successful_backend(Query::CalleesOfFunction, "callees_of", symbol, |backend| {
            callees_call(backend, symbol, position)
        })
        .await
    }
}
