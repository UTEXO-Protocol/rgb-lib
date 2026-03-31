use super::*;

pub(crate) trait RejectList {
    fn get_reject_list(self, url: &str) -> Result<String, Error>;
}

impl RejectList for RestClient {
    fn get_reject_list(self, url: &str) -> Result<String, Error> {
        Ok(self
            .get(url)
            .send()
            .map_err(|e| Error::RejectListService {
                details: e.to_string(),
            })?
            .text()
            .map_err(InternalError::from)?)
    }
}
